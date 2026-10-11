package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrMaybeChanged means ALTER ROLE was interrupted (Ctrl-C), so the server
// may or may not have applied it before the cancel arrived.
var ErrMaybeChanged = errors.New("interrupted while changing the password")

// RotateSQL returns the statement that gives role a new password. secret is
// used as described for Project.Plan.
func RotateSQL(role, secret string) string {
	return fmt.Sprintf("ALTER ROLE %s PASSWORD %s", ident(role), literal(secret))
}

// ClearExpirySQL returns the statement that lifts role's VALID UNTIL, for the
// warning after rotating an expired role.
func ClearExpirySQL(role string) string {
	return fmt.Sprintf("ALTER ROLE %s VALID UNTIL 'infinity'", ident(role))
}

// Rotation is what RotatePassword reports back besides success.
type Rotation struct {
	// Database is the role's project database, for a connection URL, or ""
	// if none was found (see projectCandidates).
	Database string
	// Expired means the role's VALID UNTIL has passed. A new password doesn't
	// change that, so the new password won't work either.
	Expired bool
	// Powers is what the role can do beyond its project that rotate-password
	// doesn't refuse (CREATEDB, owning another database, ...), as nellie list
	// shows it; nil for none. The new password carries those too.
	Powers []string
}

// RotatePassword sets a new password for role on the server described by cfg.
func RotatePassword(ctx context.Context, cfg *pgx.ConnConfig, role, password string) (Rotation, error) {
	if err := ValidateRoleName(role); err != nil {
		return Rotation{}, err
	}
	verifier, err := scramVerifier(password)
	if err != nil {
		return Rotation{}, err
	}

	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return Rotation{}, fmt.Errorf("connecting: %w", err)
	}
	defer admin.Close(context.Background())

	// The safety checks below read catalogs and use operators by unqualified name.
	if err := pinSession(ctx, admin); err != nil {
		return Rotation{}, err
	}
	if err := checkServerVersion(ctx, admin); err != nil {
		return Rotation{}, err
	}
	expired, err := checkRotatable(ctx, admin, role)
	if err != nil {
		return Rotation{}, err
	}
	// A single statement is its own transaction, so no runTx here.
	if _, err := admin.Exec(ctx, RotateSQL(role, verifier)); err != nil {
		var pgErr *pgconn.PgError
		switch {
		case ctx.Err() != nil:
			return Rotation{}, fmt.Errorf("%w: %w", ErrMaybeChanged, err)
		case errors.As(err, &pgErr) && pgErr.Code == "42501": // insufficient_privilege
			return Rotation{}, fmt.Errorf("the admin role may not change the password of role %s "+
				"(on Postgres 16 and later it needs ADMIN OPTION on the role, which it has for roles it created): %w", role, err)
		default:
			return Rotation{}, fmt.Errorf("changing the password of role %s: %w", role, err)
		}
	}

	// The password has changed by now, so a failed lookup mustn't read as a
	// failed rotation: without a database the caller just prints no URL.
	db, _ := projectDatabase(ctx, admin, role)
	powers, _ := rolePowers(ctx, admin, role, db)
	return Rotation{Database: db, Expired: expired, Powers: powers}, nil
}

// checkRotatable refuses roles whose password nellie shouldn't change:
// missing ones, ones that can't log in anyway, the admin itself (that would
// cut off the connection settings nellie was started with), superusers (a
// CREATEROLE admin isn't allowed to), and roles with powers nellie never
// gives its own roles, such as another admin, or that can SET ROLE to such a
// role through membership: taking over those is a job for psql, not a side
// effect of nellie. Membership in any predefined pg_* role counts too (they
// grant things like reading every table or signalling other sessions), except
// pg_database_owner, which Postgres reports for the owner of the current
// database. It also reports whether the role's VALID UNTIL has passed.
func checkRotatable(ctx context.Context, conn *pgx.Conn, role string) (expired bool, err error) {
	var canLogin, self, super, createRole, replication, bypassRLS bool
	var via string // a privileged role that role is a member of, or ""
	err = conn.QueryRow(ctx, `
		SELECT rolcanlogin, rolname IN (current_user, session_user),
			rolsuper, rolcreaterole, rolreplication, rolbypassrls,
			coalesce(rolvaliduntil < now(), false),
			coalesce((SELECT r.rolname FROM pg_roles r
				WHERE r.rolname <> $1::name AND pg_has_role($1::name, r.oid, 'MEMBER')
					AND (r.rolsuper OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls
						OR (r.rolname LIKE 'pg\_%' AND r.rolname <> 'pg_database_owner'))
				ORDER BY r.rolname LIMIT 1), '')
		FROM pg_roles WHERE rolname = $1::name`,
		role,
	).Scan(&canLogin, &self, &super, &createRole, &replication, &bypassRLS, &expired, &via)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false, fmt.Errorf("role %s %w", role, ErrNotFound)
	case err != nil:
		return false, fmt.Errorf("looking up role %s: %w", role, err)
	case self:
		return false, fmt.Errorf("role %s is the admin role nellie is connected as; change its password with psql's \\password instead", role)
	case super:
		return false, fmt.Errorf("role %s is a superuser; nellie only changes passwords of ordinary roles", role)
	case !canLogin:
		return false, fmt.Errorf("role %s can't log in (NOLOGIN), so a password wouldn't do anything", role)
	}

	var powers []string
	if createRole {
		powers = append(powers, "CREATEROLE")
	}
	if replication {
		powers = append(powers, "REPLICATION")
	}
	if bypassRLS {
		powers = append(powers, "BYPASSRLS")
	}
	if len(powers) > 0 {
		return false, fmt.Errorf("role %s has %s, which nellie's roles never have; change its password with psql's \\password instead",
			role, strings.Join(powers, ", "))
	}
	if via != "" {
		return false, fmt.Errorf("role %s is a member of %s, which nellie's roles never are; change its password with psql's \\password instead",
			role, via)
	}
	return expired, nil
}

// projectDatabase returns role's project database for the connection URL,
// or "" for none. It's the longest of role's projectCandidates that exists,
// by name alone, as nellie list decides (see ListSQL): picking by CONNECT
// would let a CREATEDB role create a database named like the role, which
// PUBLIC can connect to, and the URL with the new password would point there.
// A URL is only given when that database is one of the admin's projects and
// the role can connect to it; otherwise "" rather than a shorter database.
func projectDatabase(ctx context.Context, conn *pgx.Conn, role string) (string, error) {
	var db string
	var usable bool
	err := conn.QueryRow(ctx, `
		SELECT datname,
			datname NOT IN ('template0', 'template1') AND datconnlimit <> -2 -- -2 marks an invalid database
				AND pg_has_role(datdba, 'USAGE') AND datallowconn
				AND has_database_privilege($2::name, oid, 'CONNECT')
		FROM pg_database
		WHERE datname = ANY($1::text[])
		ORDER BY length(datname) DESC LIMIT 1`,
		projectCandidates(role), role,
	).Scan(&db, &usable)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !usable) {
		return "", nil
	}
	return db, err
}

// rolePowers returns role's powers beyond db (its project database, or ""),
// computed as for nellie list (powersExpr); nil for none.
func rolePowers(ctx context.Context, conn *pgx.Conn, role, db string) ([]string, error) {
	var powers []string
	err := conn.QueryRow(ctx, `WITH `+poweredCTE+`
		SELECT `+powersExpr+`
		FROM pg_roles r,
			(SELECT coalesce((SELECT oid FROM pg_database WHERE datname = $2), 0) AS project) s
		WHERE r.rolname = $1`,
		role, db,
	).Scan(&powers)
	if err != nil {
		return nil, fmt.Errorf("looking up the powers of role %s: %w", role, err)
	}
	return noneIfEmpty(powers), nil
}

// projectCandidates lists the databases role might belong to, longest first:
// the whole name (a project owner) and every prefix cut at an underscore (a
// user named <project>_<suffix>, where the project itself may contain
// underscores). "shop_v2_app" gives shop_v2_app, shop_v2, shop.
func projectCandidates(role string) []string {
	candidates := []string{role}
	for i := len(role) - 1; i > 0; i-- {
		if role[i] == '_' {
			candidates = append(candidates, role[:i])
		}
	}
	return candidates
}

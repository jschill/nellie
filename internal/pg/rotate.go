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
	// when there's no usable one (see projectHome).
	Database string
	// Expired means the role's VALID UNTIL has passed. A new password doesn't
	// change that, so the new password won't work either.
	Expired bool
	// Template means the project nellie list shows the role under is a
	// template, so any CREATEDB role can copy it, data included.
	Template bool
	// Powers is what the role can do beyond its project that rotate-password
	// doesn't refuse (CREATEDB, owning another database, ...), as nellie list
	// shows it; nil for none. The new password carries those too.
	Powers []string
	// Unchecked lists the lookups after ALTER ROLE that failed, so Database,
	// Template or Powers may be missing; nil when all ran. The password has
	// changed either way.
	Unchecked []string
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
	// Only roles of the admin's projects: on Postgres 15 a CREATEROLE admin
	// may change any ordinary role's password, including other services'.
	project, template, err := rotatableProject(ctx, admin, role)
	if err != nil {
		return Rotation{}, fmt.Errorf("looking up the project of role %q: %w", role, err)
	}
	if project == "" {
		return Rotation{}, fmt.Errorf("role %q isn't in any project nellie rotates passwords for: it must own one of the admin's projects, "+
			"or be named after one that's owned by the role named after it, as nellie's projects are (nellie list shows where it belongs); "+
			"change its password with psql's \\password instead", role)
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
	// failed rotation. It's reported in Unchecked instead, and the caller
	// warns; after a Ctrl-C both lookups fail that way.
	rot := Rotation{Expired: expired, Template: template}
	if home, usable, err := projectHome(ctx, admin, role); err != nil {
		rot.Unchecked = append(rot.Unchecked, fmt.Sprintf("finding its project database for the URL (%v)", err))
	} else if usable {
		rot.Database = home
	}
	// The powers are about the project nellie list shows the role under, so
	// the two commands agree.
	if rot.Powers, err = rolePowers(ctx, admin, role, project); err != nil {
		rot.Unchecked = append(rot.Unchecked, fmt.Sprintf("checking its powers beyond the project (%v)", err))
	}
	return rot, nil
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
						OR (starts_with(r.rolname, 'pg_') AND r.rolname <> 'pg_database_owner'))
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
		return false, fmt.Errorf("role %s is a member of %q, which nellie's roles never are; change its password with psql's \\password instead",
			role, via)
	}
	return expired, nil
}

// projectHome returns role's home database, by name alone as nellie list
// decides it (see ListSQL): the longest of role's projectCandidates that
// exists, or "" for none. usable says whether a connection URL may name it:
// it's one of the admin's projects, owned by the role named after it, and the
// role can connect to it (canConnectExpr). A URL never names a shorter
// database instead, and never one picked by access: a database's owner
// controls CONNECT, and a CREATEDB role can create a database named like a
// user, though not one owned by a role named after it.
func projectHome(ctx context.Context, conn *pgx.Conn, role string) (home string, usable bool, err error) {
	err = conn.QueryRow(ctx, `
		SELECT d.datname,
			`+isProjectExpr+` AND pg_get_userbyid(d.datdba) = d.datname
				AND `+canConnectExpr+`
		FROM pg_database d, pg_roles r
		WHERE d.datname = ANY($1::text[]) AND r.rolname = $2
		ORDER BY length(d.datname) DESC LIMIT 1`,
		projectCandidates(role), role,
	).Scan(&home, &usable)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return home, usable, err
}

// rotatableProject returns the project whose role rotate-password may change,
// or "" for none, and whether it's a template database. That's role's home
// by name (the longest database of all, as for nellie list) if it's one of
// the admin's projects owned by the role named after it, the rule a
// connection URL follows too, or else one of the admin's projects that role
// owns. The home comes first, so the powers match role's row in nellie list.
// The second half matters: a project owner with CREATEDB can create a
// database named after any role, which the admin then acts for, but not
// owned by a role of that name. And a role whose home is someone else's
// database, which nellie list shows with "belongs to", isn't the project's.
func rotatableProject(ctx context.Context, conn *pgx.Conn, role string) (project string, template bool, err error) {
	err = conn.QueryRow(ctx, `
		WITH home AS (
			SELECT oid FROM pg_database WHERE datname = ANY($1::text[])
			ORDER BY length(datname) DESC LIMIT 1
		), owner AS (
			SELECT oid FROM pg_roles WHERE rolname = $2
		)
		SELECT d.datname, d.datistemplate FROM pg_database d
		WHERE `+isProjectExpr+` AND (
			d.datdba = (SELECT oid FROM owner)
			OR (d.oid = (SELECT oid FROM home) AND pg_get_userbyid(d.datdba) = d.datname))
		ORDER BY d.oid = (SELECT oid FROM home) DESC, length(d.datname) DESC LIMIT 1`,
		projectCandidates(role), role,
	).Scan(&project, &template)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return project, template, err
}

// rolePowers returns role's powers beyond db (the project nellie list shows
// it under, or ""), computed as for nellie list (powersExpr); nil for none.
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

package pg

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// cleanupTimeout bounds the cleanup after a failure, so a hung server can't
// stop nellie from exiting.
const cleanupTimeout = 30 * time.Second

// minServerVersion is Postgres 15: from there on the public schema is owned by
// pg_database_owner and PUBLIC can't create objects in it. The grants rely on
// both.
const minServerVersion = 150000

var (
	// ErrExists means a database or role with a name nellie wants exists.
	ErrExists = errors.New("name already in use")
	// ErrNotFound means a database or role nellie was asked to use doesn't exist.
	ErrNotFound = errors.New("does not exist")
	// ErrCleanupFailed means nellie failed and then couldn't undo what it had
	// created, so a role or database may be left behind.
	ErrCleanupFailed = errors.New("cleanup failed")
)

// pinSearchPath is the first statement pinSession runs.
const pinSearchPath = "SET search_path = pg_catalog, pg_temp"

// pinSession prepares the admin connection of every command, all of
// which read catalogs and call functions by unqualified name. The owner of
// the connection database controls two settings that would mislead nellie:
//   - search_path, which can put the owner's schema first and fake pg_roles
//     (or "="), so it's pinned to pg_catalog;
//   - role (ALTER DATABASE ... SET role), which makes sessions act as another
//     role, so nellie would see and do only what that role can.
//
// The role check fails closed: a session acting as another role is refused
// unless the admin's own settings explain it (ALTER ROLE <admin> [IN
// DATABASE ...] SET role), which only the admin, or a role with power over
// it, can change. Checking the database's setting instead would race: its
// owner could clear the setting between the connect and the check.
func pinSession(ctx context.Context, conn *pgx.Conn) error {
	if _, err := conn.Exec(ctx, pinSearchPath); err != nil {
		return fmt.Errorf("setting search_path: %w", err)
	}
	var db, current, session string
	var switched, byDatabase bool
	err := conn.QueryRow(ctx, `
		SELECT current_database(), current_user, session_user,
			current_user <> session_user AND NOT EXISTS (
				SELECT FROM pg_db_role_setting s
				WHERE s.setrole = (SELECT oid FROM pg_roles WHERE rolname = session_user)
					AND s.setdatabase IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()))
					AND 'role=' || current_user = ANY (s.setconfig)),
			EXISTS (
				SELECT FROM pg_db_role_setting s
				WHERE s.setrole = 0
					AND s.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database())
					AND EXISTS (SELECT FROM unnest(s.setconfig) c WHERE starts_with(c, 'role=')))`,
	).Scan(&db, &current, &session, &switched, &byDatabase)
	if err != nil {
		return fmt.Errorf("checking the session's role: %w", err)
	}
	if switched {
		// The refusal above doesn't depend on this, so a racing owner can
		// only change the advice, not whether nellie refuses.
		cause := "a role or options parameter in the admin's connection settings (the URL, PGOPTIONS or a service file); remove it"
		if byDatabase {
			cause = fmt.Sprintf("ALTER DATABASE %q SET role, which the database's owner controls; connect the admin to another database, such as postgres", db)
		}
		// %q: the names come from the catalog, and the database's owner picks
		// the role, so they're quoted rather than sent to the terminal raw.
		return fmt.Errorf("the session acts as role %q instead of %q, and the admin's own role settings don't explain it; "+
			"the likely cause is %s", current, session, cause)
	}
	return nil
}

// Plan is SQL grouped by where and how it runs. Empty groups are skipped.
type Plan struct {
	Roles        []string // admin connection, one transaction
	CreateDB     string   // admin connection; CREATE DATABASE can't run in a transaction
	DBGrants     []string // admin connection, one transaction
	SchemaGrants []string // connected to the project database, one transaction
}

// Script renders the plan as a psql-style script, for --dry-run.
func (pl Plan) Script(dbName string) string {
	var b strings.Builder
	writeTx(&b, pl.Roles)
	if pl.CreateDB != "" {
		fmt.Fprintf(&b, "%s;\n", pl.CreateDB)
	}
	writeTx(&b, pl.DBGrants)
	if len(pl.SchemaGrants) > 0 {
		fmt.Fprintf(&b, "\\connect %s\n", dbName)
		writeTx(&b, pl.SchemaGrants)
	}
	return b.String()
}

func writeTx(b *strings.Builder, stmts []string) {
	if len(stmts) == 0 {
		return
	}
	b.WriteString("BEGIN;\n")
	for _, s := range stmts {
		fmt.Fprintf(b, "  %s;\n", s)
	}
	b.WriteString("COMMIT;\n")
}

// connectTo connects with cfg's settings, but to database db.
func connectTo(ctx context.Context, cfg *pgx.ConnConfig, db string) (*pgx.Conn, error) {
	c := cfg.Copy()
	c.Database = db
	conn, err := pgx.ConnectConfig(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("connecting to database %s: %w", db, err)
	}
	return conn, nil
}

func checkServerVersion(ctx context.Context, conn *pgx.Conn) error {
	var version int
	err := conn.QueryRow(ctx, "SELECT current_setting('server_version_num')::int").Scan(&version)
	if err != nil {
		return fmt.Errorf("checking server version: %w", err)
	}
	return checkVersion(version)
}

// checkVersion takes server_version_num, such as 150004 for 15.4.
func checkVersion(version int) error {
	if version < minServerVersion {
		return fmt.Errorf("server runs Postgres %d; nellie needs %d or newer", version/10000, minServerVersion/10000)
	}
	return nil
}

// lockAddKey is the advisory lock that add-project and add-user hold from
// their name checks until they're done, so two nellie runs can't both pass
// the checks and then create overlapping names. Advisory locks are per
// database, so this serializes runs whose admin connects to the same one.
const lockAddKey = 0x6e656c6c6965 // "nellie"

// lockAdd takes lockAddKey for the rest of conn's session; closing conn
// releases it. It waits for another run, until ctx is done.
func lockAdd(ctx context.Context, conn *pgx.Conn) error {
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(lockAddKey)); err != nil {
		return fmt.Errorf("waiting for another nellie run: %w", err)
	}
	return nil
}

// ErrAmbiguous means a new name would make nellie's name-to-project mapping
// ambiguous: list and rotate-password assign a role to the longest database
// its name matches, so names must not overlap.
var ErrAmbiguous = errors.New("name would be ambiguous")

// checkProjectNameUnambiguous refuses a project name that would move an
// existing user: a login role named <name>_... whose home (the longest
// database its name matches, as nellie list decides) is shorter than <name>
// today, or missing, would become this project's user. Roles a longer
// database already claims stay where they are, so databases alone never
// refuse a name, and neither do roles list never shows as users (NOLOGIN, the
// admin itself). The caller has pinned the session (pinSession).
func checkProjectNameUnambiguous(ctx context.Context, conn *pgx.Conn, name string) error {
	var moved []string
	err := conn.QueryRow(ctx, `
		SELECT ARRAY(SELECT r.rolname::text FROM pg_roles r
			WHERE r.rolcanlogin AND r.rolname NOT IN (current_user, session_user)
				AND starts_with(r.rolname, $1 || '_')
				AND NOT EXISTS (SELECT FROM pg_database d
					WHERE length(d.datname) > length($1)
						AND (r.rolname = d.datname OR starts_with(r.rolname, d.datname || '_')))
			ORDER BY 1)`,
		name,
	).Scan(&moved)
	if err != nil {
		return fmt.Errorf("checking for roles named %s_...: %w", name, err)
	}
	if len(moved) > 0 {
		quoted := make([]string, len(moved))
		for i, r := range moved {
			// %q-style: names come from the catalog, so no raw control
			// characters reach the terminal.
			quoted[i] = strconv.Quote(r)
		}
		return fmt.Errorf("%w: project %s would claim existing login role(s) %s as its users, since nellie tells projects apart by name prefix; pick another project name",
			ErrAmbiguous, name, strings.Join(quoted, ", "))
	}
	return nil
}

// checkUserNameUnambiguous refuses a user name that a database longer than
// its project would claim: user shop_v2_app of project shop while a database
// shop_v2 exists. The caller has pinned the session (pinSession).
func checkUserNameUnambiguous(ctx context.Context, conn *pgx.Conn, user, project string) error {
	var dbs []string
	err := conn.QueryRow(ctx, `
		SELECT ARRAY(SELECT datname::text FROM pg_database
			WHERE datname = ANY($1::text[]) AND length(datname) > length($2)
			ORDER BY length(datname) DESC)`,
		projectCandidates(user), project,
	).Scan(&dbs)
	if err != nil {
		return fmt.Errorf("checking for databases that would claim %s: %w", user, err)
	}
	if len(dbs) > 0 {
		return fmt.Errorf("%w: user %s would belong to database %q by name, not to project %s; pick another suffix",
			ErrAmbiguous, user, dbs[0], project)
	}
	return nil
}

// checkNamesFree returns ErrExists if any of the databases or roles exist.
func checkNamesFree(ctx context.Context, conn *pgx.Conn, dbs, roles []string) error {
	var takenDBs, takenRoles []string
	err := conn.QueryRow(ctx, `
		SELECT
			ARRAY(SELECT datname::text FROM pg_database WHERE datname = ANY($1::text[]) ORDER BY 1),
			ARRAY(SELECT rolname::text FROM pg_roles WHERE rolname = ANY($2::text[]) ORDER BY 1)`,
		dbs, roles,
	).Scan(&takenDBs, &takenRoles)
	if err != nil {
		return fmt.Errorf("checking for existing databases and roles: %w", err)
	}

	var taken []string
	for _, d := range takenDBs {
		taken = append(taken, "database "+d)
	}
	for _, r := range takenRoles {
		taken = append(taken, "role "+r)
	}
	if len(taken) > 0 {
		return fmt.Errorf("%w: %s", ErrExists, strings.Join(taken, ", "))
	}
	return nil
}

// execAll runs statements one by one outside a transaction and returns all
// errors, for best-effort cleanup.
func execAll(ctx context.Context, conn *pgx.Conn, stmts ...string) error {
	var errs []error
	for _, s := range stmts {
		if _, err := conn.Exec(ctx, s); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func runTx(ctx context.Context, conn *pgx.Conn, stmts []string) error {
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		for _, s := range stmts {
			if _, err := tx.Exec(ctx, s); err != nil {
				return err
			}
		}
		return nil
	})
}

// ident quotes a role or database name. Names can't be bind parameters
// ($1) in DDL, so this is the only safe way to put one into SQL.
func ident(name string) string {
	return pgx.Identifier{name}.Sanitize()
}

// literal quotes a string constant, for the few places (PASSWORD) where DDL
// can't take a bind parameter either.
func literal(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

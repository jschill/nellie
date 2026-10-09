package pg

import (
	"context"
	"errors"
	"fmt"
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

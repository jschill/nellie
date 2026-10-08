package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

const (
	ownerSuffix = "_owner"
	appSuffix   = "_app"
)

// minServerVersion is Postgres 15: from there on the public schema is owned by
// pg_database_owner and PUBLIC can't create objects in it. The grants below
// rely on both.
const minServerVersion = 150000

// ErrExists means a database or role with one of the project's names exists.
var ErrExists = errors.New("name already in use")

// Project is a database plus the two roles that use it.
type Project struct {
	Name  string // the database
	Owner string // owns the database and runs migrations
	App   string // reads and writes rows, can't change the schema
}

// NewProject validates name and derives the project's role names from it.
func NewProject(name string) (Project, error) {
	if err := ValidateProjectName(name); err != nil {
		return Project{}, err
	}
	return Project{Name: name, Owner: name + ownerSuffix, App: name + appSuffix}, nil
}

// Plan is the SQL that creates a project, grouped by where and how it runs.
type Plan struct {
	Roles        []string // admin connection, one transaction
	CreateDB     string   // admin connection; CREATE DATABASE can't run in a transaction
	DBGrants     []string // admin connection, one transaction
	SchemaGrants []string // connected to the new database, one transaction
}

// Plan returns the SQL for creating p. The secrets are used verbatim as the
// roles' PASSWORD values: SCRAM verifiers for real runs, placeholders for
// dry runs.
func (p Project) Plan(ownerSecret, appSecret string) Plan {
	db, owner, app := ident(p.Name), ident(p.Owner), ident(p.App)
	return Plan{
		Roles: []string{
			fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD %s", owner, literal(ownerSecret)),
			fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD %s", app, literal(appSecret)),
			// Since Postgres 16, CREATEROLE doesn't make us a member of the roles
			// we create, but CREATE DATABASE ... OWNER and ALTER DEFAULT
			// PRIVILEGES FOR ROLE both need that membership.
			fmt.Sprintf("GRANT %s TO CURRENT_USER", owner),
		},
		CreateDB: fmt.Sprintf("CREATE DATABASE %s OWNER %s", db, owner),
		DBGrants: []string{
			fmt.Sprintf("REVOKE CONNECT ON DATABASE %s FROM PUBLIC", db),
			fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO %s, %s", db, owner, app),
		},
		SchemaGrants: []string{
			fmt.Sprintf("GRANT USAGE ON SCHEMA public TO %s", app),
			fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %s", owner, app),
			fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %s", owner, app),
		},
	}
}

// Script renders the plan as a psql-style script, for --dry-run.
func (pl Plan) Script(dbName string) string {
	var b strings.Builder
	writeTx(&b, pl.Roles)
	fmt.Fprintf(&b, "%s;\n", pl.CreateDB)
	writeTx(&b, pl.DBGrants)
	fmt.Fprintf(&b, "\\connect %s\n", dbName)
	writeTx(&b, pl.SchemaGrants)
	return b.String()
}

func writeTx(b *strings.Builder, stmts []string) {
	b.WriteString("BEGIN;\n")
	for _, s := range stmts {
		fmt.Fprintf(b, "  %s;\n", s)
	}
	b.WriteString("COMMIT;\n")
}

// CreateProject creates p on the server described by cfg, which must connect
// as a role with CREATEROLE and CREATEDB. If a step fails after the roles are
// created, it drops everything it created.
func CreateProject(ctx context.Context, cfg *pgx.ConnConfig, p Project, ownerPassword, appPassword string) (err error) {
	ownerVerifier, err := scramVerifier(ownerPassword)
	if err != nil {
		return err
	}
	appVerifier, err := scramVerifier(appPassword)
	if err != nil {
		return err
	}
	plan := p.Plan(ownerVerifier, appVerifier)

	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}
	defer admin.Close(context.Background())

	if err := checkServerVersion(ctx, admin); err != nil {
		return err
	}
	if err := checkNotExists(ctx, admin, p); err != nil {
		return err
	}

	if err := runTx(ctx, admin, plan.Roles); err != nil {
		return fmt.Errorf("creating roles: %w", err)
	}

	// From here on a failure would leave objects behind, so undo them. This
	// runs after any return below and sees the error it returned, because err
	// is a named result.
	defer func() {
		if err == nil {
			return
		}
		// Not ctx: if the failure was ctx being cancelled (Ctrl-C), the
		// cleanup still has to run.
		if cerr := dropProject(context.Background(), cfg, p); cerr != nil {
			err = errors.Join(err, fmt.Errorf("cleanup failed, database %s and roles %s, %s may be left behind: %w",
				p.Name, p.Owner, p.App, cerr))
		}
	}()

	if _, err := admin.Exec(ctx, plan.CreateDB); err != nil {
		return fmt.Errorf("creating database: %w", err)
	}
	if err := runTx(ctx, admin, plan.DBGrants); err != nil {
		return fmt.Errorf("granting database privileges: %w", err)
	}

	projCfg := cfg.Copy()
	projCfg.Database = p.Name
	proj, err := pgx.ConnectConfig(ctx, projCfg)
	if err != nil {
		return fmt.Errorf("connecting to database %s: %w", p.Name, err)
	}
	err = runTx(ctx, proj, plan.SchemaGrants)
	// Close before returning: the cleanup can't drop a database we're connected to.
	proj.Close(context.Background())
	if err != nil {
		return fmt.Errorf("granting schema privileges: %w", err)
	}
	return nil
}

func checkServerVersion(ctx context.Context, conn *pgx.Conn) error {
	var version int
	err := conn.QueryRow(ctx, "SELECT current_setting('server_version_num')::int").Scan(&version)
	if err != nil {
		return fmt.Errorf("checking server version: %w", err)
	}
	if version < minServerVersion {
		return fmt.Errorf("server runs Postgres %d; nellie needs %d or newer", version/10000, minServerVersion/10000)
	}
	return nil
}

func checkNotExists(ctx context.Context, conn *pgx.Conn, p Project) error {
	var dbExists bool
	var roles []string
	err := conn.QueryRow(ctx, `
		SELECT
			EXISTS (SELECT 1 FROM pg_database WHERE datname = $1),
			ARRAY(SELECT rolname::text FROM pg_roles WHERE rolname = ANY($2::text[]) ORDER BY rolname)`,
		p.Name, []string{p.Owner, p.App},
	).Scan(&dbExists, &roles)
	if err != nil {
		return fmt.Errorf("checking for existing database and roles: %w", err)
	}

	var taken []string
	if dbExists {
		taken = append(taken, "database "+p.Name)
	}
	for _, r := range roles {
		taken = append(taken, "role "+r)
	}
	if len(taken) > 0 {
		return fmt.Errorf("%w: %s", ErrExists, strings.Join(taken, ", "))
	}
	return nil
}

// dropProject removes everything CreateProject may have created. It opens its
// own connection, because the caller's may be broken by whatever went wrong.
func dropProject(ctx context.Context, cfg *pgx.ConnConfig, p Project) error {
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	var errs []error
	for _, s := range []string{
		// The database first: its owner role can't be dropped while it exists.
		"DROP DATABASE IF EXISTS " + ident(p.Name),
		"DROP ROLE IF EXISTS " + ident(p.App),
		"DROP ROLE IF EXISTS " + ident(p.Owner),
	} {
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

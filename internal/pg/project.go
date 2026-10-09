package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Project is a database plus a login role with the same name that owns it and
// can do everything in it. More users are added with AddUser.
type Project struct {
	Name string
}

// NewProject validates name.
func NewProject(name string) (Project, error) {
	if err := ValidateProjectName(name); err != nil {
		return Project{}, err
	}
	return Project{Name: name}, nil
}

// Plan returns the SQL for creating p. The secret is used verbatim as the
// owner's PASSWORD value: a SCRAM verifier for real runs, a placeholder for
// dry runs.
func (p Project) Plan(secret string) Plan {
	name := ident(p.Name)
	return Plan{
		Roles: []string{
			fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD %s", name, literal(secret)),
			// Since Postgres 16, CREATEROLE doesn't make us a member of the roles
			// we create. CREATE DATABASE ... OWNER needs that membership, and so
			// do AddUser's grants later, so it stays.
			fmt.Sprintf("GRANT %s TO CURRENT_USER", name),
		},
		CreateDB: fmt.Sprintf("CREATE DATABASE %s OWNER %s", name, name),
		DBGrants: []string{
			// ALL, not just CONNECT: PUBLIC also has TEMPORARY by default, and
			// that would let app users create temp tables.
			fmt.Sprintf("REVOKE ALL ON DATABASE %s FROM PUBLIC", name),
			fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO %s", name, name),
		},
	}
}

// CreateProject creates p on the server described by cfg, which must connect
// as a role with CREATEROLE and CREATEDB. If a step fails after the role is
// created, it drops everything it created.
func CreateProject(ctx context.Context, cfg *pgx.ConnConfig, p Project, password string) (err error) {
	verifier, err := scramVerifier(password)
	if err != nil {
		return err
	}
	plan := p.Plan(verifier)

	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}
	defer admin.Close(context.Background())

	if err := checkServerVersion(ctx, admin); err != nil {
		return err
	}
	if err := checkNamesFree(ctx, admin, []string{p.Name}, []string{p.Name}); err != nil {
		return err
	}

	if err := runTx(ctx, admin, plan.Roles); err != nil {
		return fmt.Errorf("creating role: %w", err)
	}

	// From here on a failure would leave objects behind, so undo them. This
	// runs after any return below and sees the error it returned, because err
	// is a named result.
	// Only drop the database if this call created it. If another session
	// created one with this name after our check, CREATE DATABASE fails and
	// that database isn't ours to drop.
	dbCreated := false
	defer func() {
		if err == nil {
			return
		}
		// Not ctx: if the failure was ctx being cancelled (Ctrl-C), the
		// cleanup still has to run.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		if cerr := dropProject(cleanupCtx, cfg, p, dbCreated); cerr != nil {
			err = errors.Join(err, fmt.Errorf("%w, database and role %s may be left behind: %w", ErrCleanupFailed, p.Name, cerr))
		}
	}()

	if _, err := admin.Exec(ctx, plan.CreateDB); err != nil {
		return fmt.Errorf("creating database: %w", err)
	}
	dbCreated = true
	if err := runTx(ctx, admin, plan.DBGrants); err != nil {
		return fmt.Errorf("granting database privileges: %w", err)
	}
	return nil
}

// dropProject removes what CreateProject created. The database is dropped only
// if dropDB is set, meaning this call created it. The role always was created
// here, since the role transaction ran before any defer was set up. It opens
// its own connection, because the caller's may be broken by whatever went wrong.
func dropProject(ctx context.Context, cfg *pgx.ConnConfig, p Project, dropDB bool) error {
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	var stmts []string
	if dropDB {
		// The database first: its owner can't be dropped while it exists.
		stmts = append(stmts, "DROP DATABASE IF EXISTS "+ident(p.Name))
	}
	stmts = append(stmts, "DROP ROLE IF EXISTS "+ident(p.Name))
	return execAll(ctx, conn, stmts...)
}

package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// DefaultUserSuffix is appended to a project name to suggest a user name.
const DefaultUserSuffix = "_app"

// User is a login role that can read and write rows in a project's public
// schema, but can't change the schema.
type User struct {
	Name    string
	Project string // the database
}

// NewUser validates both names.
func NewUser(name, project string) (User, error) {
	if err := ValidateUserName(name); err != nil {
		return User{}, err
	}
	if err := ValidateProjectName(project); err != nil {
		return User{}, err
	}
	return User{Name: name, Project: project}, nil
}

// Plan returns the SQL for creating u. owner is the role that owns the
// project database; secret is used as described for Project.Plan.
func (u User) Plan(owner, secret string) Plan {
	user, db, own := ident(u.Name), ident(u.Project), ident(owner)
	return Plan{
		Roles: []string{
			fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD %s", user, literal(secret)),
		},
		DBGrants: []string{
			fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO %s", db, user),
		},
		SchemaGrants: []string{
			fmt.Sprintf("GRANT USAGE ON SCHEMA public TO %s", user),
			// Tables and sequences that already exist...
			fmt.Sprintf("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %s", user),
			fmt.Sprintf("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %s", user),
			// ...and the ones the owner creates later. Only the owner's: tables
			// created by any other role aren't covered.
			fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %s", own, user),
			fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %s", own, user),
		},
	}
}

// AddUser creates u in its project on the server described by cfg. If a step
// fails after the role is created, it drops the role again.
func AddUser(ctx context.Context, cfg *pgx.ConnConfig, u User, password string) (err error) {
	verifier, err := scramVerifier(password)
	if err != nil {
		return err
	}

	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}
	defer admin.Close(context.Background())

	if err := checkServerVersion(ctx, admin); err != nil {
		return err
	}
	owner, err := projectOwner(ctx, admin, u.Project)
	if err != nil {
		return err
	}
	if err := checkNamesFree(ctx, admin, nil, []string{u.Name}); err != nil {
		return err
	}
	plan := u.Plan(owner, verifier)

	if err := runTx(ctx, admin, append(plan.Roles, plan.DBGrants...)); err != nil {
		return fmt.Errorf("creating role: %w", err)
	}

	// Same pattern as CreateProject.
	defer func() {
		if err == nil {
			return
		}
		if cerr := dropUser(context.Background(), cfg, u); cerr != nil {
			err = errors.Join(err, fmt.Errorf("cleanup failed, role %s may be left behind: %w", u.Name, cerr))
		}
	}()

	proj, err := connectTo(ctx, cfg, u.Project)
	if err != nil {
		return err
	}
	err = runTx(ctx, proj, plan.SchemaGrants)
	proj.Close(context.Background())
	if err != nil {
		return fmt.Errorf("granting schema privileges: %w", err)
	}
	return nil
}

// projectOwner returns the role that owns database db, and checks that the
// admin role can act as it, which the grants in AddUser need.
func projectOwner(ctx context.Context, conn *pgx.Conn, db string) (string, error) {
	var owner string
	var canAct bool
	err := conn.QueryRow(ctx,
		"SELECT pg_get_userbyid(datdba), pg_has_role(datdba, 'USAGE') FROM pg_database WHERE datname = $1",
		db,
	).Scan(&owner, &canAct)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("database %s %w", db, ErrNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("looking up database %s: %w", db, err)
	}
	if !canAct {
		return "", fmt.Errorf("can't grant access to database %s: the admin role isn't a member of its owner %s "+
			"(projects made by nellie add-project are set up for this)", db, owner)
	}
	return owner, nil
}

// dropUser undoes the admin-connection part of AddUser. The schema grants
// run in one transaction, so if they failed there's nothing to undo there.
func dropUser(ctx context.Context, cfg *pgx.ConnConfig, u User) error {
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	return execAll(ctx, conn,
		// A role can't be dropped while it still has privileges on a database.
		fmt.Sprintf("REVOKE ALL ON DATABASE %s FROM %s", ident(u.Project), ident(u.Name)),
		"DROP ROLE IF EXISTS "+ident(u.Name),
	)
}

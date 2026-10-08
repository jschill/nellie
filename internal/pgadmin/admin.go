package pgadmin

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// DB is a connection to a single PostgreSQL database.
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) error
	// Query returns all rows of the result, with every value formatted as a string.
	Query(ctx context.Context, sql string, args ...any) ([][]string, error)
	Close(ctx context.Context) error
}

// Connector opens a connection to the named database. An empty database
// name means the default database of the connection settings.
type Connector func(ctx context.Context, database string) (DB, error)

// ErrNotFound is returned when a referenced project does not exist.
var ErrNotFound = errors.New("not found")

// Admin performs administrative tasks on a PostgreSQL server.
type Admin struct {
	connect Connector
}

// New returns an Admin that uses connect to reach the server.
func New(connect Connector) *Admin {
	return &Admin{connect: connect}
}

// Project is a database managed by nellie.
type Project struct {
	Name  string
	Owner string
}

// User is a role on the server.
type User struct {
	Name       string
	CanLogin   bool
	Superuser  bool
	CreateDB   bool
	ValidUntil string
}

// UserOptions configures a new user.
type UserOptions struct {
	// Password is optional; when empty the user is created without a password.
	Password string
	CreateDB bool
	NoLogin  bool
}

// Access is the level of access a user gets to a project.
type Access int

const (
	ReadWrite Access = iota
	ReadOnly
)

func (a *Admin) with(ctx context.Context, database string, fn func(DB) error) (err error) {
	db, err := a.connect(ctx, database)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := db.Close(ctx); err == nil && cerr != nil {
			err = cerr
		}
	}()
	return fn(db)
}

func execAll(ctx context.Context, db DB, stmts []string) error {
	for _, s := range stmts {
		if err := db.Exec(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

// execTx runs stmts inside a single transaction.
func execTx(ctx context.Context, db DB, stmts []string) error {
	if err := db.Exec(ctx, "BEGIN"); err != nil {
		return err
	}
	if err := execAll(ctx, db, stmts); err != nil {
		_ = db.Exec(ctx, "ROLLBACK")
		return err
	}
	return db.Exec(ctx, "COMMIT")
}

// CreateProject creates a database for a project. If owner is not empty the
// database is owned by that (existing) role. Access for PUBLIC is revoked so
// that only the owner and explicitly granted users can connect.
func (a *Admin) CreateProject(ctx context.Context, name, owner string) error {
	if err := ValidateName("project", name); err != nil {
		return err
	}
	create := "CREATE DATABASE " + QuoteIdent(name)
	if owner != "" {
		if err := ValidateName("owner", owner); err != nil {
			return err
		}
		create += " OWNER " + QuoteIdent(owner)
	}
	return a.with(ctx, "", func(db DB) error {
		// CREATE DATABASE cannot run inside a transaction block.
		return execAll(ctx, db, []string{
			create,
			"REVOKE ALL ON DATABASE " + QuoteIdent(name) + " FROM PUBLIC",
		})
	})
}

// DropProject drops a project's database. With force, existing connections
// to the database are terminated first (PostgreSQL 13+).
func (a *Admin) DropProject(ctx context.Context, name string, force bool) error {
	if err := ValidateName("project", name); err != nil {
		return err
	}
	stmt := "DROP DATABASE " + QuoteIdent(name)
	if force {
		stmt += " WITH (FORCE)"
	}
	return a.with(ctx, "", func(db DB) error { return db.Exec(ctx, stmt) })
}

// ListProjects lists all non-template databases.
func (a *Admin) ListProjects(ctx context.Context) ([]Project, error) {
	var out []Project
	err := a.with(ctx, "", func(db DB) error {
		rows, err := db.Query(ctx, `SELECT d.datname, pg_catalog.pg_get_userbyid(d.datdba)
FROM pg_catalog.pg_database d
WHERE NOT d.datistemplate
ORDER BY 1`)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if len(r) != 2 {
				return fmt.Errorf("unexpected row %v", r)
			}
			out = append(out, Project{Name: r[0], Owner: r[1]})
		}
		return nil
	})
	return out, err
}

// CreateUser creates a new role.
func (a *Admin) CreateUser(ctx context.Context, name string, opts UserOptions) error {
	if err := ValidateName("user", name); err != nil {
		return err
	}
	parts := []string{"CREATE ROLE", QuoteIdent(name), "WITH"}
	if opts.NoLogin {
		parts = append(parts, "NOLOGIN")
	} else {
		parts = append(parts, "LOGIN")
	}
	if opts.CreateDB {
		parts = append(parts, "CREATEDB")
	}
	if opts.Password != "" {
		hash, err := HashPassword(opts.Password)
		if err != nil {
			return err
		}
		parts = append(parts, "PASSWORD", QuoteLiteral(hash))
	}
	stmt := strings.Join(parts, " ")
	return a.with(ctx, "", func(db DB) error { return db.Exec(ctx, stmt) })
}

// DropUser drops a role.
func (a *Admin) DropUser(ctx context.Context, name string) error {
	if err := ValidateName("user", name); err != nil {
		return err
	}
	return a.with(ctx, "", func(db DB) error {
		return db.Exec(ctx, "DROP ROLE "+QuoteIdent(name))
	})
}

// SetPassword changes the password of a role.
func (a *Admin) SetPassword(ctx context.Context, name, password string) error {
	if err := ValidateName("user", name); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return a.with(ctx, "", func(db DB) error {
		return db.Exec(ctx, "ALTER ROLE "+QuoteIdent(name)+" WITH PASSWORD "+QuoteLiteral(hash))
	})
}

// SetLogin enables or disables login for a role.
func (a *Admin) SetLogin(ctx context.Context, name string, login bool) error {
	if err := ValidateName("user", name); err != nil {
		return err
	}
	attr := "NOLOGIN"
	if login {
		attr = "LOGIN"
	}
	return a.with(ctx, "", func(db DB) error {
		return db.Exec(ctx, "ALTER ROLE "+QuoteIdent(name)+" WITH "+attr)
	})
}

// ListUsers lists all roles except the predefined pg_* roles.
func (a *Admin) ListUsers(ctx context.Context) ([]User, error) {
	var out []User
	err := a.with(ctx, "", func(db DB) error {
		rows, err := db.Query(ctx, `SELECT r.rolname, r.rolcanlogin, r.rolsuper, r.rolcreatedb, COALESCE(r.rolvaliduntil::text, '')
FROM pg_catalog.pg_roles r
WHERE r.rolname !~ '^pg_'
ORDER BY 1`)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if len(r) != 5 {
				return fmt.Errorf("unexpected row %v", r)
			}
			out = append(out, User{
				Name:       r[0],
				CanLogin:   r[1] == "true",
				Superuser:  r[2] == "true",
				CreateDB:   r[3] == "true",
				ValidUntil: r[4],
			})
		}
		return nil
	})
	return out, err
}

func (a *Admin) projectOwner(ctx context.Context, db DB, project string) (string, error) {
	rows, err := db.Query(ctx, "SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_catalog.pg_database WHERE datname = $1", project)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 || len(rows[0]) == 0 {
		return "", fmt.Errorf("project %q: %w", project, ErrNotFound)
	}
	return rows[0][0], nil
}

func validateGrantArgs(user, project, schema string) error {
	if err := ValidateName("user", user); err != nil {
		return err
	}
	if err := ValidateName("project", project); err != nil {
		return err
	}
	return ValidateName("schema", schema)
}

// Grant gives user access to the tables and sequences in schema of project.
// Default privileges are set up so that objects the project owner creates
// later are accessible as well.
func (a *Admin) Grant(ctx context.Context, user, project, schema string, access Access) error {
	if err := validateGrantArgs(user, project, schema); err != nil {
		return err
	}
	u, p, s := QuoteIdent(user), QuoteIdent(project), QuoteIdent(schema)

	dbPriv, schemaPriv, tablePriv, seqPriv := "CONNECT, TEMPORARY", "USAGE, CREATE", "SELECT, INSERT, UPDATE, DELETE", "USAGE, SELECT, UPDATE"
	if access == ReadOnly {
		dbPriv, schemaPriv, tablePriv, seqPriv = "CONNECT", "USAGE", "SELECT", "SELECT"
	}

	var owner string
	err := a.with(ctx, "", func(db DB) error {
		var err error
		if owner, err = a.projectOwner(ctx, db, project); err != nil {
			return err
		}
		return db.Exec(ctx, "GRANT "+dbPriv+" ON DATABASE "+p+" TO "+u)
	})
	if err != nil {
		return err
	}
	o := QuoteIdent(owner)
	return a.with(ctx, project, func(db DB) error {
		return execTx(ctx, db, []string{
			"GRANT " + schemaPriv + " ON SCHEMA " + s + " TO " + u,
			"GRANT " + tablePriv + " ON ALL TABLES IN SCHEMA " + s + " TO " + u,
			"GRANT " + seqPriv + " ON ALL SEQUENCES IN SCHEMA " + s + " TO " + u,
			"ALTER DEFAULT PRIVILEGES FOR ROLE " + o + " IN SCHEMA " + s + " GRANT " + tablePriv + " ON TABLES TO " + u,
			"ALTER DEFAULT PRIVILEGES FOR ROLE " + o + " IN SCHEMA " + s + " GRANT " + seqPriv + " ON SEQUENCES TO " + u,
		})
	})
}

// Revoke removes all access user has to project that was given by Grant.
func (a *Admin) Revoke(ctx context.Context, user, project, schema string) error {
	if err := validateGrantArgs(user, project, schema); err != nil {
		return err
	}
	u, p, s := QuoteIdent(user), QuoteIdent(project), QuoteIdent(schema)

	var owner string
	err := a.with(ctx, "", func(db DB) error {
		var err error
		owner, err = a.projectOwner(ctx, db, project)
		return err
	})
	if err != nil {
		return err
	}
	o := QuoteIdent(owner)
	err = a.with(ctx, project, func(db DB) error {
		return execTx(ctx, db, []string{
			"ALTER DEFAULT PRIVILEGES FOR ROLE " + o + " IN SCHEMA " + s + " REVOKE ALL ON TABLES FROM " + u,
			"ALTER DEFAULT PRIVILEGES FOR ROLE " + o + " IN SCHEMA " + s + " REVOKE ALL ON SEQUENCES FROM " + u,
			"REVOKE ALL ON ALL TABLES IN SCHEMA " + s + " FROM " + u,
			"REVOKE ALL ON ALL SEQUENCES IN SCHEMA " + s + " FROM " + u,
			"REVOKE ALL ON SCHEMA " + s + " FROM " + u,
		})
	})
	if err != nil {
		return err
	}
	return a.with(ctx, "", func(db DB) error {
		return db.Exec(ctx, "REVOKE ALL ON DATABASE "+p+" FROM "+u)
	})
}

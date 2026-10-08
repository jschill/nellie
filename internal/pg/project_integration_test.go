//go:build integration

package pg

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// adminConfig returns the connection from NELLIE_TEST_DSN. Point it at a
// throwaway server, ideally as a non-superuser role with CREATEROLE and
// CREATEDB, which is the setup nellie is meant for.
func adminConfig(t *testing.T) *pgx.ConnConfig {
	t.Helper()
	dsn := os.Getenv("NELLIE_TEST_DSN")
	if dsn == "" {
		t.Skip("NELLIE_TEST_DSN not set")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// connectAs connects to the project database as one of its roles.
func connectAs(t *testing.T, admin *pgx.ConnConfig, user, password, db string) *pgx.Conn {
	t.Helper()
	cfg := admin.Copy()
	cfg.User, cfg.Password, cfg.Database = user, password, db
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("connecting as %s: %v", user, err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

// newTestProject creates a project with a random name and drops it, and any
// users named in dropUsers, when the test ends.
func newTestProject(t *testing.T, cfg *pgx.ConnConfig) (p Project, password string, dropUsers *[]string) {
	t.Helper()
	p, err := NewProject("nellie_it_" + strings.ToLower(rand.Text()[:8]))
	if err != nil {
		t.Fatal(err)
	}
	password = NewPassword()
	if err := CreateProject(context.Background(), cfg, p, password); err != nil {
		t.Fatal(err)
	}
	users := new([]string)
	t.Cleanup(func() {
		ctx := context.Background()
		if err := dropProject(ctx, cfg, p); err != nil {
			t.Errorf("dropping test project: %v", err)
		}
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		for _, u := range *users {
			if _, err := conn.Exec(ctx, "DROP ROLE IF EXISTS "+ident(u)); err != nil {
				t.Errorf("dropping test user %s: %v", u, err)
			}
		}
	})
	return p, password, users
}

func mustExec(t *testing.T, conn *pgx.Conn, sql string) {
	t.Helper()
	if _, err := conn.Exec(context.Background(), sql); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func wantDenied(t *testing.T, conn *pgx.Conn, sql string) {
	t.Helper()
	_, err := conn.Exec(context.Background(), sql)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" { // insufficient_privilege
		t.Errorf("%q should be denied, got %v", sql, err)
	}
}

func TestCreateProject(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	p, password, _ := newTestProject(t, cfg)

	t.Run("second create fails", func(t *testing.T) {
		err := CreateProject(ctx, cfg, p, NewPassword())
		if !errors.Is(err, ErrExists) {
			t.Errorf("got %v, want ErrExists", err)
		}
	})

	t.Run("public can't connect", func(t *testing.T) {
		admin, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close(ctx)
		var ok bool
		if err := admin.QueryRow(ctx, "SELECT has_database_privilege('public', $1, 'CONNECT')", p.Name).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Error("PUBLIC still has CONNECT on the project database")
		}
	})

	t.Run("owner can do everything", func(t *testing.T) {
		owner := connectAs(t, cfg, p.Name, password, p.Name)
		for _, sql := range []string{
			"CREATE TABLE notes (id serial PRIMARY KEY, body text)",
			"INSERT INTO notes (body) VALUES ('trumpety-trump')",
			"ALTER TABLE notes ADD COLUMN extra text",
			"TRUNCATE notes",
			"DROP TABLE notes",
			"CREATE SCHEMA extra",
		} {
			mustExec(t, owner, sql)
		}
	})
}

func TestAddUser(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	p, ownerPassword, dropUsers := newTestProject(t, cfg)

	// One table before the user exists, one after: both must be covered.
	owner := connectAs(t, cfg, p.Name, ownerPassword, p.Name)
	mustExec(t, owner, "CREATE TABLE before (id serial PRIMARY KEY, body text)")

	u, err := NewUser(AppUser, p.Name+"_app", p.Name)
	if err != nil {
		t.Fatal(err)
	}
	*dropUsers = append(*dropUsers, u.Name)
	appPassword := NewPassword()
	if err := AddUser(ctx, cfg, u, appPassword); err != nil {
		t.Fatal(err)
	}

	mustExec(t, owner, "CREATE TABLE after (id serial PRIMARY KEY, body text)")

	app := connectAs(t, cfg, u.Name, appPassword, p.Name)
	for _, table := range []string{"before", "after"} {
		for _, sql := range []string{
			"INSERT INTO " + table + " (body) VALUES ('trumpety-trump')", // also uses the sequence
			"SELECT * FROM " + table,
			"UPDATE " + table + " SET body = 'trump'",
			"DELETE FROM " + table,
		} {
			mustExec(t, app, sql)
		}
	}
	for _, sql := range []string{
		"CREATE TABLE more_notes (id int)",
		"DROP TABLE after",
		"ALTER TABLE before ADD COLUMN extra text",
		"TRUNCATE before",
	} {
		wantDenied(t, app, sql)
	}

	t.Run("second add fails", func(t *testing.T) {
		if err := AddUser(ctx, cfg, u, NewPassword()); !errors.Is(err, ErrExists) {
			t.Errorf("got %v, want ErrExists", err)
		}
	})

	t.Run("unknown project", func(t *testing.T) {
		missing, err := NewUser(AppUser, "nellie_it_does_not_exist_app", "nellie_it_does_not_exist")
		if err != nil {
			t.Fatal(err)
		}
		if err := AddUser(ctx, cfg, missing, NewPassword()); !errors.Is(err, ErrNotFound) {
			t.Errorf("got %v, want ErrNotFound", err)
		}
	})
}

func TestAddUserCleansUpAfterFailure(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	p, ownerPassword, dropUsers := newTestProject(t, cfg)

	// Without a public schema the schema grants fail, after the role and its
	// CONNECT grant already exist.
	owner := connectAs(t, cfg, p.Name, ownerPassword, p.Name)
	mustExec(t, owner, "DROP SCHEMA public")

	u, err := NewUser(AppUser, p.Name+"_app", p.Name)
	if err != nil {
		t.Fatal(err)
	}
	*dropUsers = append(*dropUsers, u.Name) // in case cleanup doesn't work
	err = AddUser(ctx, cfg, u, NewPassword())
	if err == nil {
		t.Fatal("AddUser succeeded without a public schema")
	}
	if strings.Contains(err.Error(), "cleanup failed") {
		t.Fatalf("cleanup failed: %v", err)
	}

	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	var exists bool
	if err := admin.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)", u.Name).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Errorf("role %s still exists after a failed AddUser", u.Name)
	}
}

func TestAddAdminUser(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	p, _, dropUsers := newTestProject(t, cfg)

	app, err := NewUser(AppUser, p.Name+"_app", p.Name)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := NewUser(AdminUser, p.Name+"_admin", p.Name)
	if err != nil {
		t.Fatal(err)
	}
	*dropUsers = append(*dropUsers, app.Name, admin.Name)
	appPassword, adminPassword := NewPassword(), NewPassword()
	for _, u := range []struct {
		user     User
		password string
	}{{app, appPassword}, {admin, adminPassword}} {
		if err := AddUser(ctx, cfg, u.user, u.password); err != nil {
			t.Fatalf("adding %s: %v", u.user.Name, err)
		}
	}

	conn := connectAs(t, cfg, admin.Name, adminPassword, p.Name)
	var current, session string
	if err := conn.QueryRow(ctx, "SELECT current_user, session_user").Scan(&current, &session); err != nil {
		t.Fatal(err)
	}
	if current != p.Name || session != admin.Name {
		t.Errorf("current_user = %s, session_user = %s; want %s acting as %s", current, session, admin.Name, p.Name)
	}

	// What the admin user creates belongs to the owner...
	mustExec(t, conn, "CREATE TABLE made_by_admin (id serial PRIMARY KEY, body text)")
	var tableOwner string
	if err := conn.QueryRow(ctx, "SELECT tableowner FROM pg_tables WHERE tablename = 'made_by_admin'").Scan(&tableOwner); err != nil {
		t.Fatal(err)
	}
	if tableOwner != p.Name {
		t.Errorf("table owner = %s, want %s", tableOwner, p.Name)
	}
	mustExec(t, conn, "ALTER TABLE made_by_admin ADD COLUMN extra text")

	// ...so the app user, added before the table existed, can use it.
	appConn := connectAs(t, cfg, app.Name, appPassword, p.Name)
	mustExec(t, appConn, "INSERT INTO made_by_admin (body) VALUES ('trumpety-trump')")
	wantDenied(t, appConn, "DROP TABLE made_by_admin")

	mustExec(t, conn, "DROP TABLE made_by_admin")
}

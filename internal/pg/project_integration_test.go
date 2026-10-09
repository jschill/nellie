//go:build integration

package pg

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestMain sweeps leftovers before and after the run. Per-test cleanups don't
// run if the process is killed (Ctrl-C, a panic, a timeout), so without this a
// crashed run would leave nellie_it_* databases and roles behind for good.
// (TestMain is a special name: `go test` calls it instead of running the tests
// directly, and the process exits with whatever code it passes to os.Exit.)
func TestMain(m *testing.M) {
	dsn := os.Getenv("NELLIE_TEST_DSN")
	if dsn == "" {
		os.Exit(m.Run()) // every test skips itself
	}
	sweep(dsn)
	code := m.Run()
	sweep(dsn)
	os.Exit(code)
}

// sweep drops every database and role whose name starts with nellie_it_.
func sweep(dsn string) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sweep: connecting:", err)
		return
	}
	defer conn.Close(ctx)

	rows, err := conn.Query(ctx, `SELECT d.datname, r.rolname FROM pg_database d
		JOIN pg_roles r ON r.oid = d.datdba WHERE d.datname LIKE 'nellie\_it\_%'`)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sweep: listing databases:", err)
		return
	}
	type dbOwner struct{ db, owner string }
	var dbs []dbOwner
	for rows.Next() {
		var d dbOwner
		if err := rows.Scan(&d.db, &d.owner); err == nil {
			dbs = append(dbs, d)
		}
	}
	rows.Close()

	// Dropping a database needs membership in its owner, which some tests
	// deliberately revoke. Granting it again is harmless if already held.
	var me string
	_ = conn.QueryRow(ctx, "SELECT current_user").Scan(&me)
	for _, d := range dbs {
		exec := func(sql string) {
			if _, err := conn.Exec(ctx, sql); err != nil {
				fmt.Fprintf(os.Stderr, "sweep: %s: %v\n", sql, err)
			}
		}
		exec("GRANT " + ident(d.owner) + " TO " + ident(me))
		exec("DROP DATABASE IF EXISTS " + ident(d.db))
	}

	rows, err = conn.Query(ctx, `SELECT rolname FROM pg_roles WHERE rolname LIKE 'nellie\_it\_%'`)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sweep: listing roles:", err)
		return
	}
	var roles []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err == nil {
			roles = append(roles, r)
		}
	}
	rows.Close()
	for _, r := range roles {
		if _, err := conn.Exec(ctx, "DROP ROLE IF EXISTS "+ident(r)); err != nil {
			fmt.Fprintf(os.Stderr, "sweep: dropping role %s: %v\n", r, err)
		}
	}
}

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
		if err := dropProject(ctx, cfg, p, true); err != nil {
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
		"CREATE TEMP TABLE scratch (id int)", // TEMPORARY is a privilege too
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

// Value: protects=CreateProject dropping the role it made when a later step fails, so a failed add-project doesn't leave a half-made project behind; fails_when=the deferred cleanup in CreateProject is removed or stops dropping the role; why_new=the existing cleanup test covers AddUser only, and CreateProject's cleanup has no test; seam=none (a CREATEROLE role without CREATEDB makes CREATE DATABASE fail for real)
func TestCreateProjectCleansUpAfterFailure(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	suffix := strings.ToLower(rand.Text()[:8])
	p, err := NewProject("nellie_it_" + suffix)
	if err != nil {
		t.Fatal(err)
	}
	limited := "nellie_it_limited_" + suffix
	limitedPassword := NewPassword()

	setup, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, setup, "CREATE ROLE "+ident(limited)+" LOGIN PASSWORD "+literal(limitedPassword)+" CREATEROLE NOCREATEDB")
	setup.Close(ctx)

	t.Cleanup(func() {
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Errorf("connecting for cleanup: %v", err)
			return
		}
		defer conn.Close(ctx)
		for _, stmt := range []string{"DROP ROLE IF EXISTS " + ident(p.Name), "DROP ROLE IF EXISTS " + ident(limited)} {
			if _, err := conn.Exec(ctx, stmt); err != nil {
				t.Errorf("%s: %v", stmt, err)
			}
		}
	})

	// The role can create the project role, but not the database.
	limitedCfg := cfg.Copy()
	limitedCfg.User, limitedCfg.Password = limited, limitedPassword
	err = CreateProject(ctx, limitedCfg, p, NewPassword())
	if err == nil {
		t.Fatal("CreateProject succeeded without CREATEDB")
	}
	if !strings.Contains(err.Error(), "creating database:") {
		t.Errorf("failed at the wrong step, want CREATE DATABASE: %v", err)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Errorf("want a permission error, got %v", err)
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
	if err := admin.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)", p.Name).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Errorf("role %s still exists after a failed CreateProject", p.Name)
	}
}

// Value: protects=AddUser refusing a project whose owner the admin role can't act as, before it creates any role, with a message that says why; fails_when=the projectOwner membership check is removed or moved after the role is created, so the grants fail halfway or a stray role is left; why_new=the membership check and its message have no test; seam=none (a database owned by a role the admin isn't a member of, made the way the server allows)
func TestAddUserNeedsMembershipInOwner(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	suffix := strings.ToLower(rand.Text()[:8])
	db := "nellie_it_" + suffix
	owner := db + "_owner"

	// CREATE DATABASE ... OWNER needs membership in the owner, so the admin
	// is granted it, creates the database, and loses it again.
	setup, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, setup, "CREATE ROLE "+ident(owner)+" NOLOGIN")
	mustExec(t, setup, "GRANT "+ident(owner)+" TO "+ident(cfg.User))
	mustExec(t, setup, "CREATE DATABASE "+ident(db)+" OWNER "+ident(owner))
	mustExec(t, setup, "REVOKE "+ident(owner)+" FROM "+ident(cfg.User))
	setup.Close(ctx)

	t.Cleanup(func() {
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Errorf("connecting for cleanup: %v", err)
			return
		}
		defer conn.Close(ctx)
		// Dropping the database needs membership in its owner, as above.
		for _, stmt := range []string{
			"GRANT " + ident(owner) + " TO " + ident(cfg.User),
			"DROP DATABASE IF EXISTS " + ident(db),
			"REVOKE " + ident(owner) + " FROM " + ident(cfg.User),
			"DROP ROLE IF EXISTS " + ident(owner),
		} {
			if _, err := conn.Exec(ctx, stmt); err != nil {
				t.Errorf("%s: %v", stmt, err)
			}
		}
	})

	u, err := NewUser(AppUser, db+"_app", db)
	if err != nil {
		t.Fatal(err)
	}
	err = AddUser(ctx, cfg, u, NewPassword())
	if err == nil {
		t.Fatal("AddUser succeeded for a database whose owner the admin isn't a member of")
	}
	if !strings.Contains(err.Error(), "isn't a member of its owner "+owner) {
		t.Errorf("unexpected error: %v", err)
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
		t.Errorf("role %s was created although AddUser refused the project", u.Name)
	}
}

// Value: protects=the app user's privileges being limited to the owner's tables, so an app user can't read or write tables another role creates in the project; fails_when=the ALTER DEFAULT PRIVILEGES loses its FOR ROLE owner clause and starts covering whichever role runs it; why_new=TestAddUser checks tables the owner creates, not the negative case the code comment promises; seam=none (the admin role is granted CREATE on public and creates a table itself)
func TestAddUserIgnoresOtherRolesTables(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	p, ownerPassword, dropUsers := newTestProject(t, cfg)

	app, err := NewUser(AppUser, p.Name+"_app", p.Name)
	if err != nil {
		t.Fatal(err)
	}
	*dropUsers = append(*dropUsers, app.Name)
	appPassword := NewPassword()
	if err := AddUser(ctx, cfg, app, appPassword); err != nil {
		t.Fatal(err)
	}

	owner := connectAs(t, cfg, p.Name, ownerPassword, p.Name)
	mustExec(t, owner, "GRANT CREATE ON SCHEMA public TO "+ident(cfg.User))

	admin := connectAs(t, cfg, cfg.User, cfg.Password, p.Name)
	mustExec(t, admin, "CREATE TABLE made_by_admin_role (id serial PRIMARY KEY, body text)")

	appConn := connectAs(t, cfg, app.Name, appPassword, p.Name)
	wantDenied(t, appConn, "SELECT * FROM made_by_admin_role")
	wantDenied(t, appConn, "INSERT INTO made_by_admin_role (body) VALUES ('trumpety-trump')")
}

// Value: protects=a database that already exists under a project's name is never dropped by the create path (the pre-create check refuses it) or by cleanup run with dbCreated false; fails_when=either path drops a database this call didn't create; why_new=the pre-create check and the dropDB flag guard the destructive DROP DATABASE, and no test pins either; seam=none
func TestCreateProjectKeepsExistingDatabase(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	name := "nellie_it_" + strings.ToLower(rand.Text()[:8])
	p, err := NewProject(name)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+ident(name))
		admin.Close(context.Background())
	})
	mustExec(t, admin, "CREATE DATABASE "+ident(name))

	if err := CreateProject(ctx, cfg, p, NewPassword()); !errors.Is(err, ErrExists) {
		t.Fatalf("got %v, want ErrExists", err)
	}
	var exists bool
	if err := admin.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)", name).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("CreateProject dropped a database it didn't create")
	}
}

// Value: protects=cleanup never drops a database this call didn't create: with dropDB false it removes the role and leaves the database; fails_when=the flag is ignored and the database is dropped; why_new=dropProject's dropDB branch has no test, and it's the guard for the race where another session creates the database first; seam=none
func TestDropProjectKeepsDatabaseWhenNotCreated(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	name := "nellie_it_" + strings.ToLower(rand.Text()[:8])
	p, err := NewProject(name)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+ident(name))
		admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+ident(name))
		admin.Close(context.Background())
	})
	mustExec(t, admin, "CREATE DATABASE "+ident(name))
	mustExec(t, admin, "CREATE ROLE "+ident(name))

	// The role was ours to drop; the database was not, so it must survive.
	if err := dropProject(ctx, cfg, p, false); err != nil {
		t.Fatal(err)
	}
	var dbExists, roleExists bool
	if err := admin.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)", name).Scan(&dbExists); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)", name).Scan(&roleExists); err != nil {
		t.Fatal(err)
	}
	if !dbExists {
		t.Error("dropProject dropped a database it was told not to")
	}
	if roleExists {
		t.Error("dropProject left the role behind")
	}
}

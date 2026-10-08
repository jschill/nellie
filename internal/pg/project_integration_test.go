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

func TestCreateProject(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)

	p, err := NewProject("nellie_it_" + strings.ToLower(rand.Text()[:8]))
	if err != nil {
		t.Fatal(err)
	}
	ownerPassword, appPassword := NewPassword(), NewPassword()

	if err := CreateProject(ctx, cfg, p, ownerPassword, appPassword); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := dropProject(context.Background(), cfg, p); err != nil {
			t.Errorf("dropping test project: %v", err)
		}
	})

	t.Run("second create fails", func(t *testing.T) {
		err := CreateProject(ctx, cfg, p, NewPassword(), NewPassword())
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

	// The owner creates the schema, as a migration would. Everything after
	// that depends on it, so these steps aren't subtests.
	owner := connectAs(t, cfg, p.Owner, ownerPassword, p.Name)
	if _, err := owner.Exec(ctx, "CREATE TABLE notes (id serial PRIMARY KEY, body text)"); err != nil {
		t.Fatalf("owner creating a table: %v", err)
	}

	app := connectAs(t, cfg, p.App, appPassword, p.Name)
	for _, sql := range []string{
		"INSERT INTO notes (body) VALUES ('trumpety-trump')",
		"SELECT * FROM notes",
		"UPDATE notes SET body = 'trump'",
		"DELETE FROM notes",
	} {
		if _, err := app.Exec(ctx, sql); err != nil {
			t.Errorf("app should be allowed %q: %v", sql, err)
		}
	}
	for _, sql := range []string{
		"CREATE TABLE more_notes (id int)",
		"DROP TABLE notes",
		"ALTER TABLE notes ADD COLUMN extra text",
		"TRUNCATE notes",
	} {
		_, err := app.Exec(ctx, sql)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" { // insufficient_privilege
			t.Errorf("app should be denied %q, got %v", sql, err)
		}
	}
}

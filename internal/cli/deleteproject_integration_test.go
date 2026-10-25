//go:build integration

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jschill/nellie/internal/pg"
)

func TestDeleteProjectCommand(t *testing.T) {
	dsn := deleteTestDSN(t)
	clearConnEnv(t)
	t.Setenv("DATABASE_URL", dsn)
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	name := "nellie_cli_it_" + strings.ToLower(rand.Text()[:8])
	p, err := pg.NewProject(name)
	if err != nil {
		t.Fatal(err)
	}
	if err = pg.CreateProject(ctx, cfg, p, pg.NewPassword()); err != nil {
		t.Fatal(err)
	}
	roles := []string{name, name + "_app", name + "_admin"}
	t.Cleanup(func() {
		c, e := pgx.ConnectConfig(ctx, cfg)
		if e != nil {
			t.Error(e)
			return
		}
		defer c.Close(ctx)
		c.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize())
		for _, r := range roles {
			c.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{r}.Sanitize())
		}
	})
	for i, kind := range []pg.UserKind{pg.AppUser, pg.AdminUser} {
		u, e := pg.NewUser(kind, roles[i+1], name)
		if e != nil {
			t.Fatal(e)
		}
		if e = pg.AddUser(ctx, cfg, u, pg.NewPassword()); e != nil {
			t.Fatal(e)
		}
	}
	exists := func() bool {
		t.Helper()
		var b bool
		if e := conn.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)", name).Scan(&b); e != nil {
			t.Fatal(e)
		}
		return b
	}
	run := func(input string, args ...string) (int, string, string) {
		t.Helper()
		var out, errout bytes.Buffer
		code := Run(args, strings.NewReader(input), &out, &errout)
		return code, out.String(), errout.String()
	}
	t.Run("dry run", func(t *testing.T) {
		code, out, errout := run("", "delete-project", "--dry-run", name)
		if code != 0 {
			t.Fatalf("code %d: %s", code, errout)
		}
		for _, s := range []string{"DROP DATABASE " + pgx.Identifier{name}.Sanitize(), "DROP ROLE " + pgx.Identifier{roles[1]}.Sanitize(), "BEGIN;", "COMMIT;"} {
			if !strings.Contains(out, s) {
				t.Errorf("missing %q in %s", s, out)
			}
		}
		if !exists() {
			t.Fatal("dry run deleted database")
		}
	})
	for _, input := range []string{"", "yes\n", name + "_wrong\n"} {
		t.Run("refuses "+input, func(t *testing.T) {
			code, _, errout := run(input, "delete-project", name)
			if code == 0 || !exists() {
				t.Fatalf("code %d: %s", code, errout)
			}
		})
	}
	t.Run("confirmed", func(t *testing.T) {
		code, out, errout := run(name+"\n", "delete-project", name)
		if code != 0 {
			t.Fatalf("code %d: %s", code, errout)
		}
		if !strings.Contains(errout, roles[1]) || !strings.Contains(errout, roles[2]) {
			t.Errorf("preview missing roles: %s", errout)
		}
		if exists() {
			t.Error("database remains")
		}
		var remaining int
		if e := conn.QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname=ANY($1)", roles).Scan(&remaining); e != nil {
			t.Fatal(e)
		}
		if remaining != 0 {
			t.Errorf("%d roles remain: %s", remaining, out)
		}
	})
}

func TestDeleteProjectSafety(t *testing.T) {
	dsn := deleteTestDSN(t)
	clearConnEnv(t)
	t.Setenv("DATABASE_URL", dsn)
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, scenario := range []string{"foreign owner", "template", "owner powers", "user powers", "external dependency", "current database", "active session", "missing", "nested project", "nologin user", "changed roles", "replaced database", "replaced role"} {
		t.Run(scenario, func(t *testing.T) {
			name := "nellie_cli_it_" + strings.ToLower(rand.Text()[:8])
			p, _ := pg.NewProject(name)
			if e := pg.CreateProject(ctx, cfg, p, pg.NewPassword()); e != nil {
				t.Fatal(e)
			}
			conn, e := pgx.ConnectConfig(ctx, cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close(ctx)
			exec := func(sql string) {
				t.Helper()
				if _, e := conn.Exec(ctx, sql); e != nil {
					t.Fatal(e)
				}
			}
			user := name + "_app"
			u, _ := pg.NewUser(pg.AppUser, user, name)
			if e := pg.AddUser(ctx, cfg, u, pg.NewPassword()); e != nil {
				t.Fatal(e)
			}
			nested := name + "_nested"
			roles := []string{user, name, nested + "_app", nested}
			t.Cleanup(func() {
				c, e := pgx.ConnectConfig(ctx, cfg)
				if e != nil {
					t.Error(e)
					return
				}
				defer c.Close(ctx)
				for _, db := range []string{nested, name} {
					c.Exec(ctx, "ALTER DATABASE "+pgx.Identifier{db}.Sanitize()+" IS_TEMPLATE false")
					c.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{db}.Sanitize())
				}
				c.Exec(ctx, "DROP TABLE IF EXISTS "+pgx.Identifier{name}.Sanitize())
				for _, r := range roles {
					c.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{r}.Sanitize())
				}
			})
			wantErr := ""
			switch scenario {
			case "foreign owner":
				exec("ALTER DATABASE " + pgx.Identifier{name}.Sanitize() + " OWNER TO CURRENT_USER")
				wantErr = "owned by"
			case "template":
				exec("ALTER DATABASE " + pgx.Identifier{name}.Sanitize() + " IS_TEMPLATE true")
				wantErr = "non-template"
			case "owner powers":
				exec("ALTER ROLE " + pgx.Identifier{name}.Sanitize() + " CREATEDB")
				wantErr = "powers outside"
			case "user powers":
				exec("ALTER ROLE " + pgx.Identifier{user}.Sanitize() + " CREATEDB")
				wantErr = "powers outside"
			case "external dependency":
				exec("CREATE DATABASE " + pgx.Identifier{nested}.Sanitize())
				local := cfg.Copy()
				local.Database = nested
				external, e := pgx.ConnectConfig(ctx, local)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = external.Exec(ctx, "CREATE TABLE external_data (id int); GRANT SELECT ON external_data TO "+pgx.Identifier{user}.Sanitize()); e != nil {
					t.Fatal(e)
				}
				external.Close(ctx)
				wantErr = "dependencies outside"
			case "current database":
				local := cfg.Copy()
				local.Database = name
				t.Setenv("DATABASE_URL", dsn+"&dbname="+name)
				wantErr = "current connection"
			case "active session":
				local := cfg.Copy()
				local.Database = name
				active, e := pgx.ConnectConfig(ctx, local)
				if e != nil {
					t.Fatal(e)
				}
				defer active.Close(ctx)
				wantErr = "roles were not dropped"
			case "missing":
				exec("DROP DATABASE " + pgx.Identifier{name}.Sanitize())
				wantErr = "does not exist"
			case "nested project":
				np, _ := pg.NewProject(nested)
				if e := pg.CreateProject(ctx, cfg, np, pg.NewPassword()); e != nil {
					t.Fatal(e)
				}
				nu, _ := pg.NewUser(pg.AppUser, nested+"_app", nested)
				if e := pg.AddUser(ctx, cfg, nu, pg.NewPassword()); e != nil {
					t.Fatal(e)
				}
			case "nologin user":
				exec("ALTER ROLE " + pgx.Identifier{user}.Sanitize() + " NOLOGIN")
			case "replaced role":
				// An ungranted role can be replaced without changing the names in the plan.
				extra := name + "_extra"
				roles = append(roles, extra)
				exec("CREATE ROLE " + pgx.Identifier{extra}.Sanitize() + " LOGIN")
				input := &deleteConfirmationReader{answer: strings.NewReader(name + "\n"), before: func() {
					exec("DROP ROLE " + pgx.Identifier{extra}.Sanitize())
					exec("CREATE ROLE " + pgx.Identifier{extra}.Sanitize() + " LOGIN")
				}}
				var out, errout bytes.Buffer
				code := Run([]string{"delete-project", name}, input, &out, &errout)
				if code == 0 || !strings.Contains(errout.String(), "changed during confirmation") {
					t.Fatalf("code %d: %s", code, &errout)
				}
				return
			case "replaced database":
				input := &deleteConfirmationReader{answer: strings.NewReader(name + "\n"), before: func() {
					exec("DROP DATABASE " + pgx.Identifier{name}.Sanitize())
					exec("CREATE DATABASE " + pgx.Identifier{name}.Sanitize() + " OWNER " + pgx.Identifier{name}.Sanitize())
				}}
				var out, errout bytes.Buffer
				code := Run([]string{"delete-project", name}, input, &out, &errout)
				if code == 0 || !strings.Contains(errout.String(), "changed during confirmation") {
					t.Fatalf("code %d: %s", code, &errout)
				}
				return
			case "changed roles":
				// A reader changes the catalog only after the preview, when confirmation is requested.
				input := &deleteConfirmationReader{answer: strings.NewReader(name + "\n"), before: func() { exec("ALTER ROLE " + pgx.Identifier{user}.Sanitize() + " CREATEDB") }}
				var out, errout bytes.Buffer
				code := Run([]string{"delete-project", name}, input, &out, &errout)
				if code == 0 || !strings.Contains(errout.String(), "powers outside") {
					t.Fatalf("code %d: %s", code, &errout)
				}
				return
			}
			var out, errout bytes.Buffer
			code := Run([]string{"delete-project", name}, strings.NewReader(name+"\n"), &out, &errout)
			if wantErr != "" {
				if code != exitError || !strings.Contains(errout.String(), wantErr) {
					t.Fatalf("code %d, want %q: %s", code, wantErr, &errout)
				}
				if scenario != "missing" {
					var exists bool
					if e := conn.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)", name).Scan(&exists); e != nil {
						t.Fatal(e)
					}
					if !exists {
						t.Fatal("refusal deleted database")
					}
				}
				return
			}
			if code != 0 {
				t.Fatalf("code %d: %s", code, &errout)
			}
			if scenario == "nested project" {
				var count int
				if e := conn.QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname=ANY($1)", []string{nested, nested + "_app"}).Scan(&count); e != nil {
					t.Fatal(e)
				}
				if count != 2 {
					t.Errorf("nested project's roles deleted: %d remain", count)
				}
				if strings.Contains(errout.String(), "  "+nested+"\n") {
					t.Error("preview includes nested owner")
				}
			}
			if scenario == "nologin user" {
				var exists bool
				if e := conn.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1)", user).Scan(&exists); e != nil {
					t.Fatal(e)
				}
				if exists {
					t.Error("NOLOGIN user remains")
				}
			}
		})
	}
}

type deleteConfirmationReader struct {
	answer *strings.Reader
	before func()
}

func (r *deleteConfirmationReader) Read(b []byte) (int, error) {
	if r.before != nil {
		r.before()
		r.before = nil
	}
	return r.answer.Read(b)
}

func deleteTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("NELLIE_TEST_DSN")
	if dsn == "" {
		t.Skip("NELLIE_TEST_DSN not set")
	}
	if !strings.Contains(dsn, "sslmode=") {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		dsn += sep + "sslmode=disable"
	}
	return dsn
}

// A failed preview or confirmation prompt must not authorize a destructive run.
func TestDeleteProjectRequiresWritablePreview(t *testing.T) {
	dsn := deleteTestDSN(t)
	clearConnEnv(t)
	t.Setenv("DATABASE_URL", dsn)
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, section := range []string{"warning", "roles", "prompt"} {
		t.Run(section, func(t *testing.T) {
			name := "nellie_cli_it_" + strings.ToLower(rand.Text()[:8])
			p, _ := pg.NewProject(name)
			if err := pg.CreateProject(ctx, cfg, p, pg.NewPassword()); err != nil {
				t.Fatal(err)
			}
			conn, err := pgx.ConnectConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize())
				conn.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{name}.Sanitize())
				conn.Close(ctx)
			})
			marker := "Permanently delete"
			if section == "roles" {
				marker = "  " + name
			}
			if section == "prompt" {
				marker = "Type the project name"
			}
			var out bytes.Buffer
			preview := &failedDeletionPreview{at: marker}
			code := Run([]string{"delete-project", name}, strings.NewReader(name+"\n"), &out, preview)
			var dbExists, roleExists bool
			if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1), EXISTS(SELECT FROM pg_roles WHERE rolname=$1)`, name).Scan(&dbExists, &roleExists); err != nil {
				t.Fatal(err)
			}
			if code != exitError || !dbExists || !roleExists {
				t.Fatalf("code=%d database=%t role=%t, output=%q", code, dbExists, roleExists, out.String())
			}
			if !strings.Contains(preview.String(), "nothing deleted") {
				t.Errorf("missing cancellation explanation: %s", preview.String())
			}
		})
	}
}

type failedDeletionPreview struct {
	bytes.Buffer
	at string
}

func (w *failedDeletionPreview) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.at) {
		return 0, io.ErrClosedPipe
	}
	return w.Buffer.Write(p)
}

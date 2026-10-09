//go:build integration

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Value: protects=the whole rotate-password command against a real server: a generated password is printed once (in JSON and the URL) and works, a typed one (spaces included) works but never reaches stdout, the URL names the longest matching project database, and a role without one gets no URL; fails_when=a typed password is echoed, the --json field names or omitempty change, the lookup picks a shorter project prefix, or a missing database breaks the output; why_new=only --dry-run and the pieces were tested, nothing ran rotatePassword itself; seam=none
func TestRotatePasswordCommand(t *testing.T) {
	dsn := os.Getenv("NELLIE_TEST_DSN")
	if dsn == "" {
		t.Skip("NELLIE_TEST_DSN not set")
	}
	// nellie requires TLS unless sslmode=disable is asked for; the throwaway
	// test server has no TLS, so ask for it unless the DSN says otherwise.
	if !strings.Contains(dsn, "sslmode=") {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		dsn += sep + "sslmode=disable"
	}
	clearConnEnv(t)
	t.Setenv("DATABASE_URL", dsn)

	ctx := context.Background()
	adminCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.ConnectConfig(ctx, adminCfg)
	if err != nil {
		t.Fatal(err)
	}
	// t.Cleanup, not defer: deferred calls run before the cleanups below,
	// which still need this connection to drop what the test created.
	t.Cleanup(func() { admin.Close(context.Background()) })
	exec := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}

	// Not "nellie_it_": go test runs packages in parallel, and the pg
	// package's sweep of that prefix would drop these mid-test. Two databases,
	// so the role <base>_v2_app has two candidate projects.
	base := "nellie_cli_it_" + strings.ToLower(rand.Text()[:8])
	project := base + "_v2"
	user := project + "_app"
	for _, db := range []string{base, project} {
		exec("CREATE DATABASE " + pgx.Identifier{db}.Sanitize())
	}
	exec("CREATE ROLE " + pgx.Identifier{user}.Sanitize() + " LOGIN")
	t.Cleanup(func() {
		for _, sql := range []string{
			"DROP ROLE IF EXISTS " + pgx.Identifier{user}.Sanitize(),
			"DROP DATABASE IF EXISTS " + pgx.Identifier{project}.Sanitize(),
			"DROP DATABASE IF EXISTS " + pgx.Identifier{base}.Sanitize(),
		} {
			admin.Exec(context.Background(), sql)
		}
	})

	// orphan has no project database at all.
	orphan := "nellie_cli_it_orphan_" + strings.ToLower(rand.Text()[:8])
	exec("CREATE ROLE " + pgx.Identifier{orphan}.Sanitize() + " LOGIN")
	t.Cleanup(func() { admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+pgx.Identifier{orphan}.Sanitize()) })

	// canLogIn checks that password opens database db (postgres if "") as role.
	canLogIn := func(t *testing.T, role, password, db string) {
		t.Helper()
		c := adminCfg.Copy()
		c.User, c.Password, c.Database = role, password, db
		if db == "" {
			c.Database = "postgres"
		}
		conn, err := pgx.ConnectConfig(ctx, c)
		if err != nil {
			t.Fatalf("logging in as %s with the new password: %v", role, err)
		}
		conn.Close(ctx)
	}
	// run returns stdout and stderr separately: a typed password must be in
	// neither.
	run := func(t *testing.T, stdin string, args ...string) (stdout, stderr string) {
		t.Helper()
		var out, errOut bytes.Buffer
		if code := Run(append([]string{"rotate-password"}, args...), strings.NewReader(stdin), &out, &errOut); code != exitOK {
			t.Fatalf("exit code %d, stderr:\n%s", code, errOut.String())
		}
		return out.String(), errOut.String()
	}

	t.Run("generated, json", func(t *testing.T) {
		out, _ := run(t, "", user, "--json", "--generate")
		var res map[string]string
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("stdout isn't JSON: %v\n%s", err, out)
		}
		if res["user"] != user || res["database"] != project {
			t.Errorf("user = %q, database = %q; want %q and the longest project %q", res["user"], res["database"], user, project)
		}
		if len(res["password"]) != 26 {
			t.Fatalf("password = %q, want a 26-character generated one", res["password"])
		}
		got, err := pgx.ParseConfig(res["url"])
		if err != nil {
			t.Fatalf("url doesn't parse: %v", err)
		}
		if got.User != user || got.Password != res["password"] || got.Database != project {
			t.Errorf("url = %s, want user %s, the generated password and database %s", res["url"], user, project)
		}
		canLogIn(t, user, res["password"], project)
	})

	const typed = "  correct horse battery staple  "
	t.Run("typed, human", func(t *testing.T) {
		// Value: protects=a typed password reaches neither stdout nor stderr (prompts, warnings, errors); fails_when=a message starts quoting the input; why_new=only stdout was checked; seam=none
		out, errOut := run(t, typed+"\n", user)
		if strings.Contains(out+errOut, strings.TrimSpace(typed)) {
			t.Errorf("output shows the typed password:\nstdout:\n%s\nstderr:\n%s", out, errOut)
		}
		if !strings.Contains(out, "postgres://"+user+"@") {
			t.Errorf("stdout lacks a URL without password:\n%s", out)
		}
		canLogIn(t, user, typed, project) // spaces and all
	})

	t.Run("typed, json", func(t *testing.T) {
		out, errOut := run(t, typed+"\n", "--json", user)
		if strings.Contains(out+errOut, strings.TrimSpace(typed)) || strings.Contains(out, `"password"`) {
			t.Errorf("output shows the typed password:\nstdout:\n%s\nstderr:\n%s", out, errOut)
		}
		canLogIn(t, user, typed, project)
	})

	// Value: protects=a rotation whose output can't be written says so and exits 1 instead of losing the only copy of a generated password silently; fails_when=stdout write errors are ignored again; why_new=red team review; seam=none
	t.Run("output can't be written", func(t *testing.T) {
		var stderr bytes.Buffer
		code := Run([]string{"rotate-password", "--generate", user}, strings.NewReader(""), failingWriter{}, &stderr)
		if code != exitError || !strings.Contains(stderr.String(), "was changed, but the result couldn't be written") {
			t.Errorf("exit code %d, stderr:\n%s", code, stderr.String())
		}
		if regexp.MustCompile(`[A-Z2-7]{26}`).MatchString(stderr.String()) {
			t.Errorf("stderr shows a generated password:\n%s", stderr.String())
		}
	})

	// Value: protects=an expired VALID UNTIL is reported on stderr while --json stdout stays valid JSON; fails_when=the warning is dropped or printed to stdout; why_new=only pg.Rotation.Expired was tested; seam=none
	t.Run("expired role warns on stderr", func(t *testing.T) {
		expired := "nellie_cli_it_exp_" + strings.ToLower(rand.Text()[:8])
		exec("CREATE ROLE " + pgx.Identifier{expired}.Sanitize() + " LOGIN VALID UNTIL '2000-01-01'")
		t.Cleanup(func() { admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+pgx.Identifier{expired}.Sanitize()) })

		var stdout, stderr bytes.Buffer
		if code := Run([]string{"rotate-password", "--json", "--generate", expired}, strings.NewReader(""), &stdout, &stderr); code != exitOK {
			t.Fatalf("exit code %d, stderr:\n%s", code, stderr.String())
		}
		var res map[string]string
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("stdout isn't JSON: %v\n%s", err, stdout.String())
		}
		if !strings.Contains(stderr.String(), "VALID UNTIL") || strings.Contains(stdout.String(), "VALID UNTIL") {
			t.Errorf("the warning belongs on stderr only; stdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
		}
	})

	t.Run("no project database", func(t *testing.T) {
		out, _ := run(t, "", orphan, "--json", "--generate")
		var res map[string]string
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("stdout isn't JSON: %v\n%s", err, out)
		}
		if _, ok := res["database"]; ok {
			t.Errorf("database present without a project: %s", out)
		}
		if _, ok := res["url"]; ok {
			t.Errorf("url present without a project: %s", out)
		}
		canLogIn(t, orphan, res["password"], "")

		human, _ := run(t, "", orphan, "--generate")
		if !strings.Contains(human, "password: ") || strings.Contains(human, "postgres://") {
			t.Errorf("without a URL the generated password should be printed on its own:\n%s", human)
		}
	})
}

// failingWriter is a stdout that can't be written to, like a full disk.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

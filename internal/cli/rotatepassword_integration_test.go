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
	"slices"
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
	// Each owned by the role named after it, as nellie's projects are: only
	// those get a URL.
	for _, db := range []string{base, project} {
		id := pgx.Identifier{db}.Sanitize()
		exec("CREATE ROLE " + id + " NOLOGIN")
		exec("GRANT " + id + " TO " + pgx.Identifier{adminCfg.User}.Sanitize())
		exec("CREATE DATABASE " + id + " OWNER " + id)
	}
	exec("CREATE ROLE " + pgx.Identifier{user}.Sanitize() + " LOGIN")
	t.Cleanup(func() {
		for _, sql := range []string{
			"DROP ROLE IF EXISTS " + pgx.Identifier{user}.Sanitize(),
			"DROP DATABASE IF EXISTS " + pgx.Identifier{project}.Sanitize(),
			"DROP DATABASE IF EXISTS " + pgx.Identifier{base}.Sanitize(),
			"DROP ROLE IF EXISTS " + pgx.Identifier{project}.Sanitize(),
			"DROP ROLE IF EXISTS " + pgx.Identifier{base}.Sanitize(),
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

	// decode reads rotate-password's --json output, as a result and as raw
	// fields (to tell a missing field from an empty one).
	decode := func(t *testing.T, out string) (rotateResult, map[string]json.RawMessage) {
		t.Helper()
		var res rotateResult
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("stdout isn't JSON: %v\n%s", err, out)
		}
		json.Unmarshal([]byte(out), &raw)
		return res, raw
	}

	t.Run("generated, json", func(t *testing.T) {
		out, _ := run(t, "", user, "--json", "--generate")
		res, raw := decode(t, out)
		if res.User != user || res.Database != project {
			t.Errorf("user = %q, database = %q; want %q and the longest project %q", res.User, res.Database, user, project)
		}
		if len(res.Password) != 26 {
			t.Fatalf("password = %q, want a 26-character generated one", res.Password)
		}
		got, err := pgx.ParseConfig(res.URL)
		if err != nil {
			t.Fatalf("url doesn't parse: %v", err)
		}
		if got.User != user || got.Password != res.Password || got.Database != project {
			t.Errorf("url = %s, want user %s, the generated password and database %s", res.URL, user, project)
		}
		// Value: protects=the warning fields are always present for scripts, [] not null for no powers; fails_when=a field gets omitempty or a nil slice; why_new=new fields; seam=none
		if string(raw["powers"]) != "[]" || string(raw["expired"]) != "false" || string(raw["template"]) != "false" {
			t.Errorf("warning fields = powers %s, expired %s, template %s; want [], false, false", raw["powers"], raw["expired"], raw["template"])
		}
		canLogIn(t, user, res.Password, project)
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

	// Value: protects=powers beyond the project are warned about on stderr and listed in --json's powers field; fails_when=the warning or the field is dropped; why_new=new warning; seam=none
	t.Run("powers warn on stderr", func(t *testing.T) {
		maker := "nellie_cli_it_pow_" + strings.ToLower(rand.Text()[:8])
		exec("CREATE ROLE " + pgx.Identifier{maker}.Sanitize() + " LOGIN CREATEDB")
		t.Cleanup(func() { admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+pgx.Identifier{maker}.Sanitize()) })

		var stdout, stderr bytes.Buffer
		if code := Run([]string{"rotate-password", "--json", "--generate", maker}, strings.NewReader(""), &stdout, &stderr); code != exitOK {
			t.Fatalf("exit code %d, stderr:\n%s", code, stderr.String())
		}
		res, _ := decode(t, stdout.String())
		if !strings.Contains(stderr.String(), "powers beyond its project (CREATEDB)") || !slices.Equal(res.Powers, []string{"CREATEDB"}) {
			t.Errorf("want the warning on stderr and powers [CREATEDB] in --json; stdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
		}
	})

	// Value: protects=a template project database is warned about on stderr and flagged in --json; fails_when=the template flag stops reaching Rotation, or the warning or field is dropped; no_claim=the role's home and shown project are the same database here; why_new=Rotation.Template was only ever false in tests; seam=none
	t.Run("template home warns on stderr", func(t *testing.T) {
		// What the project's owner could do; the admin acts for the owner.
		exec("ALTER DATABASE " + pgx.Identifier{project}.Sanitize() + " IS_TEMPLATE true")
		// A template can't be dropped, so this runs before the test's cleanup.
		t.Cleanup(func() {
			if _, err := admin.Exec(context.Background(), "ALTER DATABASE "+pgx.Identifier{project}.Sanitize()+" IS_TEMPLATE false"); err != nil {
				t.Errorf("turning IS_TEMPLATE off again: %v", err)
			}
		})

		var stdout, stderr bytes.Buffer
		if code := Run([]string{"rotate-password", "--json", "--generate", user}, strings.NewReader(""), &stdout, &stderr); code != exitOK {
			t.Fatalf("exit code %d, stderr:\n%s", code, stderr.String())
		}
		res, _ := decode(t, stdout.String())
		if !strings.Contains(stderr.String(), "role "+user+" is a template") || !res.Template {
			t.Errorf("want the warning on stderr and template true in --json; stdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
		}
	})

	// Value: protects=an expired VALID UNTIL is reported on stderr and as expired in --json; fails_when=the warning or the field is dropped, or the warning goes to stdout; why_new=only pg.Rotation.Expired was tested; seam=none
	t.Run("expired role warns on stderr", func(t *testing.T) {
		expired := "nellie_cli_it_exp_" + strings.ToLower(rand.Text()[:8])
		exec("CREATE ROLE " + pgx.Identifier{expired}.Sanitize() + " LOGIN VALID UNTIL '2000-01-01'")
		t.Cleanup(func() { admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+pgx.Identifier{expired}.Sanitize()) })

		var stdout, stderr bytes.Buffer
		if code := Run([]string{"rotate-password", "--json", "--generate", expired}, strings.NewReader(""), &stdout, &stderr); code != exitOK {
			t.Fatalf("exit code %d, stderr:\n%s", code, stderr.String())
		}
		res, _ := decode(t, stdout.String())
		if !strings.Contains(stderr.String(), "VALID UNTIL") || strings.Contains(stdout.String(), "VALID UNTIL") || !res.Expired {
			t.Errorf("want the warning on stderr only and expired true in --json; stdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
		}
	})

	t.Run("no project database", func(t *testing.T) {
		out, _ := run(t, "", orphan, "--json", "--generate")
		res, raw := decode(t, out)
		if _, ok := raw["database"]; ok {
			t.Errorf("database present without a project: %s", out)
		}
		if _, ok := raw["url"]; ok {
			t.Errorf("url present without a project: %s", out)
		}
		canLogIn(t, orphan, res.Password, "")

		human, _ := run(t, "", orphan, "--generate")
		if !strings.Contains(human, "password: ") || strings.Contains(human, "postgres://") {
			t.Errorf("without a URL the generated password should be printed on its own:\n%s", human)
		}
	})
}

// failingWriter is a stdout that can't be written to, like a full disk.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

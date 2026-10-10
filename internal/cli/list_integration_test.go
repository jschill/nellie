//go:build integration

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Value: protects=list against a real server: --json in the documented shape with users [] for a user-less project, trumpet's human layout, exit 1 when stdout fails; fails_when=list() stops wiring ListProjects to its output, the LEFT JOIN drops user-less projects, or write errors are ignored; why_new=list() only ran as a dry run; seam=none
func TestListCommand(t *testing.T) {
	dsn := os.Getenv("NELLIE_TEST_DSN")
	if dsn == "" {
		t.Skip("NELLIE_TEST_DSN not set")
	}
	// The throwaway test server has no TLS; see TestRotatePasswordCommand.
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
	// t.Cleanup, not defer: the cleanups below still need this connection.
	t.Cleanup(func() { admin.Close(context.Background()) })
	exec := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}

	// Not "nellie_it_", which the pg package sweeps in parallel. The admin
	// creates both databases, so it owns them and list shows them.
	base := "nellie_cli_it_" + strings.ToLower(rand.Text()[:8])
	empty, full := base+"_empty", base+"_full"
	user := full + "_app"
	for _, db := range []string{empty, full} {
		exec("CREATE DATABASE " + pgx.Identifier{db}.Sanitize())
	}
	exec("CREATE ROLE " + pgx.Identifier{user}.Sanitize() + " LOGIN")
	t.Cleanup(func() {
		for _, sql := range []string{
			"DROP ROLE IF EXISTS " + pgx.Identifier{user}.Sanitize(),
			"DROP DATABASE IF EXISTS " + pgx.Identifier{full}.Sanitize(),
			"DROP DATABASE IF EXISTS " + pgx.Identifier{empty}.Sanitize(),
		} {
			admin.Exec(context.Background(), sql)
		}
	})

	run := func(t *testing.T, args ...string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code := Run(args, strings.NewReader(""), &stdout, &stderr); code != exitOK {
			t.Fatalf("exit code %d, stderr:\n%s", code, stderr.String())
		}
		return stdout.String()
	}

	t.Run("json", func(t *testing.T) {
		out := run(t, "list", "--json")
		var got []listProject
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("stdout isn't JSON: %v\n%s", err, out)
		}
		// The server may hold other projects; only the test's matter.
		byName := map[string]listProject{}
		for _, p := range got {
			byName[p.Project] = p
		}
		want := []listProject{
			{Project: empty, Owner: adminCfg.User, Users: []listUser{}},
			{Project: full, Owner: adminCfg.User, Users: []listUser{{Name: user, Type: "application", CanConnect: true}}},
		}
		for _, w := range want {
			if g := byName[w.Project]; !reflect.DeepEqual(g, w) {
				t.Errorf("got  %+v\nwant %+v", g, w)
			}
		}
		// [] rather than null: Unmarshal turns both into an empty slice, so
		// look at the raw value.
		var raw []map[string]json.RawMessage
		if err := json.Unmarshal([]byte(out), &raw); err != nil {
			t.Fatal(err)
		}
		for _, p := range raw {
			if string(p["project"]) == `"`+empty+`"` && string(p["users"]) != "[]" {
				t.Errorf("users of a project without users = %s, want []", p["users"])
			}
		}
	})

	t.Run("trumpet, human", func(t *testing.T) {
		out := run(t, "trumpet")
		for _, block := range []string{
			empty + "  (owner " + adminCfg.User + ")\n  no users yet; add one with \"nellie add-user\"\n",
			full + "  (owner " + adminCfg.User + ")\n  " + user + "  application\n",
		} {
			if !strings.Contains(out, block) {
				t.Errorf("output lacks\n%s\ngot:\n%s", block, out)
			}
		}
	})

	t.Run("output can't be written", func(t *testing.T) {
		var stderr bytes.Buffer
		code := Run([]string{"list"}, strings.NewReader(""), failingWriter{}, &stderr)
		if code != exitError || !strings.Contains(stderr.String(), "writing the list") {
			t.Errorf("exit code %d, stderr:\n%s", code, stderr.String())
		}
	})
}

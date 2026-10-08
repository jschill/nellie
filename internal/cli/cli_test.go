package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jschill/nellie/internal/pgadmin"
)

type call struct {
	db  string
	sql string
}

// fakeServer records statements executed through it and answers queries
// with canned rows.
type fakeServer struct {
	calls   []call
	rows    map[string][][]string // keyed by a substring of the query
	failSQL string
}

type fakeDB struct {
	s    *fakeServer
	name string
}

func (d *fakeDB) Exec(_ context.Context, sql string, _ ...any) error {
	d.s.calls = append(d.s.calls, call{d.name, sql})
	if d.s.failSQL != "" && strings.Contains(sql, d.s.failSQL) {
		return errors.New("boom")
	}
	return nil
}

func (d *fakeDB) Query(_ context.Context, sql string, _ ...any) ([][]string, error) {
	for k, v := range d.s.rows {
		if strings.Contains(sql, k) {
			return v, nil
		}
	}
	return nil, nil
}

func (d *fakeDB) Close(context.Context) error { return nil }

func run(t *testing.T, s *fakeServer, stdin string, passwords []string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	app := &App{
		Stdin:  strings.NewReader(stdin),
		Stdout: &out,
		Stderr: &errOut,
		Getenv: func(string) string { return "" },
		Connect: func(string) (pgadmin.Connector, error) {
			return func(_ context.Context, db string) (pgadmin.DB, error) {
				return &fakeDB{s: s, name: db}, nil
			}, nil
		},
		ReadPassword: func(string) (string, error) {
			if len(passwords) == 0 {
				return "", errors.New("no terminal")
			}
			pw := passwords[0]
			passwords = passwords[1:]
			return pw, nil
		},
	}
	code := app.Run(context.Background(), args)
	return code, out.String(), errOut.String()
}

func sqls(s *fakeServer) []string {
	var out []string
	for _, c := range s.calls {
		out = append(out, c.sql)
	}
	return out
}

func assertSQL(t *testing.T, s *fakeServer, want ...string) {
	t.Helper()
	got := sqls(s)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("executed SQL:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestProjectAdd(t *testing.T) {
	s := &fakeServer{}
	code, out, errOut := run(t, s, "", nil, "project", "add", "shop", "--owner", "shop_owner")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	assertSQL(t, s,
		`CREATE DATABASE "shop" OWNER "shop_owner"`,
		`REVOKE ALL ON DATABASE "shop" FROM PUBLIC`,
	)
	if !strings.Contains(out, `Created project "shop"`) {
		t.Errorf("unexpected output %q", out)
	}
}

func TestProjectAddQuotesNames(t *testing.T) {
	s := &fakeServer{}
	if code, _, errOut := run(t, s, "", nil, "project", "add", `x"; DROP DATABASE postgres; --`); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	assertSQL(t, s,
		`CREATE DATABASE "x""; DROP DATABASE postgres; --"`,
		`REVOKE ALL ON DATABASE "x""; DROP DATABASE postgres; --" FROM PUBLIC`,
	)
}

func TestProjectRemove(t *testing.T) {
	s := &fakeServer{}
	if code, _, errOut := run(t, s, "", nil, "project", "remove", "--force", "shop"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	assertSQL(t, s, `DROP DATABASE "shop" WITH (FORCE)`)
}

func TestProjectList(t *testing.T) {
	s := &fakeServer{rows: map[string][][]string{"pg_database": {{"postgres", "postgres"}, {"shop", "shop_owner"}}}}
	code, out, errOut := run(t, s, "", nil, "project", "list")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	want := "NAME      OWNER\npostgres  postgres\nshop      shop_owner\n"
	if out != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}

func TestUserAdd(t *testing.T) {
	s := &fakeServer{}
	if code, _, errOut := run(t, s, "", nil, "user", "add", "alice", "--createdb"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	assertSQL(t, s, `CREATE ROLE "alice" WITH LOGIN CREATEDB`)

	s = &fakeServer{}
	if code, _, errOut := run(t, s, "", nil, "user", "add", "--nologin", "group"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	assertSQL(t, s, `CREATE ROLE "group" WITH NOLOGIN`)
}

func TestUserAddPasswordIsHashed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		stdin     string
		passwords []string
		args      []string
	}{
		{"stdin", "s3cret'pw\n", nil, []string{"user", "add", "bob", "--password-stdin"}},
		{"prompt", "", []string{"s3cret'pw", "s3cret'pw"}, []string{"user", "add", "bob", "-W"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &fakeServer{}
			code, _, errOut := run(t, s, tc.stdin, tc.passwords, tc.args...)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, errOut)
			}
			got := sqls(s)
			if len(got) != 1 || !strings.HasPrefix(got[0], `CREATE ROLE "bob" WITH LOGIN PASSWORD 'SCRAM-SHA-256$4096:`) {
				t.Fatalf("unexpected SQL %q", got)
			}
			if strings.Contains(got[0], "s3cret") {
				t.Errorf("plaintext password sent to server: %s", got[0])
			}
		})
	}
}

func TestUserPasswdMismatch(t *testing.T) {
	s := &fakeServer{}
	code, _, errOut := run(t, s, "", []string{"one", "two"}, "user", "passwd", "bob")
	if code != 1 || !strings.Contains(errOut, "passwords do not match") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if len(s.calls) != 0 {
		t.Errorf("unexpected SQL %q", sqls(s))
	}
}

func TestUserPasswdNoTerminal(t *testing.T) {
	s := &fakeServer{}
	code, _, errOut := run(t, s, "", nil, "user", "passwd", "bob")
	if code != 1 || !strings.Contains(errOut, "no terminal") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}

func TestUserPasswd(t *testing.T) {
	s := &fakeServer{}
	if code, _, errOut := run(t, s, "newpw\n", nil, "user", "passwd", "bob", "--password-stdin"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	got := sqls(s)
	if len(got) != 1 || !strings.HasPrefix(got[0], `ALTER ROLE "bob" WITH PASSWORD 'SCRAM-SHA-256$4096:`) {
		t.Fatalf("unexpected SQL %q", got)
	}
}

func TestUserRemoveLockUnlock(t *testing.T) {
	s := &fakeServer{}
	for _, args := range [][]string{
		{"user", "lock", "bob"},
		{"user", "unlock", "bob"},
		{"user", "remove", "bob"},
	} {
		if code, _, errOut := run(t, s, "", nil, args...); code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, errOut)
		}
	}
	assertSQL(t, s,
		`ALTER ROLE "bob" WITH NOLOGIN`,
		`ALTER ROLE "bob" WITH LOGIN`,
		`DROP ROLE "bob"`,
	)
}

func TestUserList(t *testing.T) {
	s := &fakeServer{rows: map[string][][]string{"pg_roles": {
		{"alice", "true", "false", "true", ""},
		{"postgres", "true", "true", "true", ""},
	}}}
	code, out, errOut := run(t, s, "", nil, "user", "list")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	want := "NAME      LOGIN  SUPERUSER  CREATEDB  VALID UNTIL\n" +
		"alice     yes    no         yes       \n" +
		"postgres  yes    yes        yes       \n"
	if out != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}

func TestUserGrant(t *testing.T) {
	s := &fakeServer{rows: map[string][][]string{"pg_database": {{"shop_owner"}}}}
	if code, _, errOut := run(t, s, "", nil, "user", "grant", "bob", "shop"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	assertSQL(t, s,
		`GRANT CONNECT, TEMPORARY ON DATABASE "shop" TO "bob"`,
		`BEGIN`,
		`GRANT USAGE, CREATE ON SCHEMA "public" TO "bob"`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "public" TO "bob"`,
		`GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA "public" TO "bob"`,
		`ALTER DEFAULT PRIVILEGES FOR ROLE "shop_owner" IN SCHEMA "public" GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "bob"`,
		`ALTER DEFAULT PRIVILEGES FOR ROLE "shop_owner" IN SCHEMA "public" GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO "bob"`,
		`COMMIT`,
	)
	if s.calls[0].db != "" || s.calls[1].db != "shop" {
		t.Errorf("statements ran in wrong databases: %+v", s.calls)
	}
}

func TestUserGrantReadOnly(t *testing.T) {
	s := &fakeServer{rows: map[string][][]string{"pg_database": {{"shop_owner"}}}}
	if code, _, errOut := run(t, s, "", nil, "user", "grant", "--readonly", "--schema", "app", "bob", "shop"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	assertSQL(t, s,
		`GRANT CONNECT ON DATABASE "shop" TO "bob"`,
		`BEGIN`,
		`GRANT USAGE ON SCHEMA "app" TO "bob"`,
		`GRANT SELECT ON ALL TABLES IN SCHEMA "app" TO "bob"`,
		`GRANT SELECT ON ALL SEQUENCES IN SCHEMA "app" TO "bob"`,
		`ALTER DEFAULT PRIVILEGES FOR ROLE "shop_owner" IN SCHEMA "app" GRANT SELECT ON TABLES TO "bob"`,
		`ALTER DEFAULT PRIVILEGES FOR ROLE "shop_owner" IN SCHEMA "app" GRANT SELECT ON SEQUENCES TO "bob"`,
		`COMMIT`,
	)
}

func TestUserGrantRollsBackOnError(t *testing.T) {
	s := &fakeServer{rows: map[string][][]string{"pg_database": {{"shop_owner"}}}, failSQL: "ON ALL SEQUENCES"}
	code, _, errOut := run(t, s, "", nil, "user", "grant", "bob", "shop")
	if code != 1 || !strings.Contains(errOut, "boom") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	got := sqls(s)
	if got[len(got)-1] != "ROLLBACK" {
		t.Errorf("expected ROLLBACK, got %q", got)
	}
}

func TestUserGrantUnknownProject(t *testing.T) {
	s := &fakeServer{}
	code, _, errOut := run(t, s, "", nil, "user", "grant", "bob", "nope")
	if code != 1 || !strings.Contains(errOut, `project "nope": not found`) {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if len(s.calls) != 0 {
		t.Errorf("unexpected SQL %q", sqls(s))
	}
}

func TestUserRevoke(t *testing.T) {
	s := &fakeServer{rows: map[string][][]string{"pg_database": {{"shop_owner"}}}}
	if code, _, errOut := run(t, s, "", nil, "user", "revoke", "bob", "shop"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	assertSQL(t, s,
		`BEGIN`,
		`ALTER DEFAULT PRIVILEGES FOR ROLE "shop_owner" IN SCHEMA "public" REVOKE ALL ON TABLES FROM "bob"`,
		`ALTER DEFAULT PRIVILEGES FOR ROLE "shop_owner" IN SCHEMA "public" REVOKE ALL ON SEQUENCES FROM "bob"`,
		`REVOKE ALL ON ALL TABLES IN SCHEMA "public" FROM "bob"`,
		`REVOKE ALL ON ALL SEQUENCES IN SCHEMA "public" FROM "bob"`,
		`REVOKE ALL ON SCHEMA "public" FROM "bob"`,
		`COMMIT`,
		`REVOKE ALL ON DATABASE "shop" FROM "bob"`,
	)
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"project"},
		{"bogus", "cmd"},
		{"project", "add"},
		{"project", "add", "a", "b"},
		{"user", "add", "bob", "--unknown"},
		{"user", "grant", "bob"},
		{"user", "add", "bob", "-W", "--password-stdin"},
	} {
		s := &fakeServer{}
		code, _, errOut := run(t, s, "", nil, args...)
		if code != 2 {
			t.Errorf("%q: exit %d, want 2 (%s)", args, code, errOut)
		}
		if len(s.calls) != 0 {
			t.Errorf("%q: unexpected SQL %q", args, sqls(s))
		}
	}
}

func TestHelp(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"-h"}, {"user", "add", "-h"}} {
		code, out, _ := run(t, &fakeServer{}, "", nil, args...)
		if code != 0 || !strings.Contains(out, "Usage:") {
			t.Errorf("%q: exit %d, output %q", args, code, out)
		}
	}
}

func TestPositionalAfterDoubleDash(t *testing.T) {
	s := &fakeServer{}
	if code, _, errOut := run(t, s, "", nil, "user", "add", "--", "-weird"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	assertSQL(t, s, `CREATE ROLE "-weird" WITH LOGIN`)
}

func TestDSNFromFlagAndEnv(t *testing.T) {
	var got []string
	app := &App{
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
		Getenv: func(k string) string {
			if k == "NELLIE_DSN" {
				return "postgres://env"
			}
			return ""
		},
		Connect: func(dsn string) (pgadmin.Connector, error) {
			got = append(got, dsn)
			return func(_ context.Context, db string) (pgadmin.DB, error) {
				return &fakeDB{s: &fakeServer{}, name: db}, nil
			}, nil
		},
	}
	app.Run(context.Background(), []string{"user", "list"})
	app.Run(context.Background(), []string{"--dsn", "postgres://flag", "user", "list"})
	if strings.Join(got, ",") != "postgres://env,postgres://flag" {
		t.Errorf("got DSNs %q", got)
	}
}

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jschill/nellie/internal/pg"
)

// Value: protects=--dry-run prints the search_path pin and the exact query, needs no connection, under both names; fails_when=the alias is dropped, the pin is left out, or the dry run connects; why_new=new code; seam=none
func TestListDryRun(t *testing.T) {
	clearConnEnv(t)
	for _, name := range []string{"list", "trumpet"} {
		t.Run(name, func(t *testing.T) {
			// Empty stdin: if it asked for the connection, it would fail.
			var stdout, stderr bytes.Buffer
			if code := Run([]string{name, "--dry-run"}, strings.NewReader(""), &stdout, &stderr); code != exitOK {
				t.Fatalf("exit code %d, stderr:\n%s", code, stderr.String())
			}
			// The search_path pin first: without it the query can run a
			// function the database's owner planted (TestListProjectsIgnoresShadowedFunctions).
			if !strings.Contains(stdout.String(), "SET search_path = pg_catalog, pg_temp;\n"+pg.ListSQL+";\n") {
				t.Errorf("dry run doesn't print the search_path pin and the query:\n%s", stdout.String())
			}
		})
	}
}

// Value: protects=usage errors exit 2 before any prompt; fails_when=list accepts an argument or combines --json with --dry-run; why_new=new code; seam=none
func TestListUsageErrors(t *testing.T) {
	clearConnEnv(t)
	for _, args := range [][]string{
		{"list", "shop"},
		{"list", "--json", "--dry-run"},
	} {
		var stdout, stderr bytes.Buffer
		if code := Run(args, strings.NewReader(""), &stdout, &stderr); code != exitUsage {
			t.Errorf("%v: exit code %d, want %d; stderr:\n%s", args, code, exitUsage, stderr.String())
		}
	}
}

// Value: protects=the human output aligns users, shows powers and expiry notes, says when there are no users, and escapes control characters; fails_when=the layout changes, an empty note column adds trailing spaces, or a raw escape sequence reaches the terminal; why_new=new code; seam=none
func TestPrintList(t *testing.T) {
	var out bytes.Buffer
	printList(&out, []pg.ProjectInfo{
		{Name: "blog", Owner: "blog"},
		{Name: "shop", Owner: "alice", Users: []pg.UserInfo{
			{Name: "shop_admin", Kind: pg.AdminUser},
			{Name: "shop_app", Kind: pg.AppUser, Expired: true},
			{Name: "shop_boss", Kind: pg.AdminUser, Powers: "CREATEROLE, member of pg_monitor", Expired: true},
			{Name: "shop_\x1b[2J", Kind: pg.AppUser},
		}},
	})
	want := `blog  (owner blog)
  no users yet; add one with "nellie add-user"

shop  (owner alice)
  shop_admin      admin
  shop_app        application  VALID UNTIL has passed, so it can't log in
  shop_boss       privileged   CREATEROLE, member of pg_monitor; VALID UNTIL has passed, so it can't log in
  "shop_\x1b[2J"  application
`
	if out.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", out.String(), want)
	}

	out.Reset()
	printList(&out, nil)
	if !strings.Contains(out.String(), "nellie add-project") {
		t.Errorf("no hint for an empty list:\n%s", out.String())
	}
}

// Value: protects=the --json shape scripts rely on: field names, the three type names, [] rather than null; fails_when=a tag or type name changes, privileged loses to the kind, or a nil slice reaches the encoder; why_new=new code; seam=none
func TestListJSON(t *testing.T) {
	tests := []struct {
		name     string
		projects []pg.ProjectInfo
		want     string
	}{
		{"no projects", nil, `[]`},
		{"no users", []pg.ProjectInfo{{Name: "blog", Owner: "blog"}}, `[{"project":"blog","owner":"blog","users":[]}]`},
		{"users", []pg.ProjectInfo{{Name: "shop", Owner: "shop", Users: []pg.UserInfo{
			{Name: "shop_admin", Kind: pg.AdminUser},
			{Name: "shop_app", Kind: pg.AppUser, Expired: true},
			{Name: "shop_boss", Kind: pg.AdminUser, Powers: "CREATEROLE"},
		}}}, `[{"project":"shop","owner":"shop","users":[` +
			`{"name":"shop_admin","type":"admin","expired":false},` +
			`{"name":"shop_app","type":"application","expired":true},` +
			`{"name":"shop_boss","type":"privileged","expired":false}]}]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(listJSON(tt.projects))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

// Value: protects=no project, owner or user name reaches the terminal with raw control or bidi characters, whichever column it is in; fails_when=printable() is dropped from the project or owner column; why_new=TestPrintList only puts the escape in a user name; seam=none
func TestPrintListEscapesEveryName(t *testing.T) {
	// ESC (clears the screen), a newline (forges a line) and U+202E (reverses text).
	hostile := "x\x1b[2J\n" + string(rune(0x202e))
	quoted := `"x\x1b[2J\n\` + `u202e"`
	tests := []struct {
		name    string
		project pg.ProjectInfo
	}{
		{"project", pg.ProjectInfo{Name: hostile, Owner: "o"}},
		{"owner", pg.ProjectInfo{Name: "p", Owner: hostile}},
		{"user", pg.ProjectInfo{Name: "p", Owner: "o", Users: []pg.UserInfo{{Name: hostile}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			printList(&out, []pg.ProjectInfo{tt.project})
			got := out.String()
			if strings.ContainsAny(got, "\x1b"+string(rune(0x202e))) || strings.Contains(got, "x\n") {
				t.Errorf("raw control characters in the output: %q", got)
			}
			if !strings.Contains(got, quoted) {
				t.Errorf("output lacks the escaped name %s: %q", quoted, got)
			}
		})
	}
}

// Value: protects=an unreachable server is exit 1 with the error on stderr, never an empty list on stdout, and the admin password isn't echoed; fails_when=the ListProjects error is dropped and list prints "The big top is empty" with exit 0; why_new=only dry runs and usage errors reach list(); seam=none
func TestListConnectionFailure(t *testing.T) {
	clearConnEnv(t)
	const secret = "S3cr3tPW"
	// Port 1 on loopback: nothing listens there, so the connection is refused at once.
	t.Setenv("DATABASE_URL", "postgres://admin:"+secret+"@127.0.0.1:1/postgres?sslmode=disable&connect_timeout=5")
	for _, args := range [][]string{{"list"}, {"list", "--json"}} {
		var stdout, stderr bytes.Buffer
		if code := Run(args, strings.NewReader(""), &stdout, &stderr); code != exitError {
			t.Errorf("%v: exit code %d, want %d; stderr:\n%s", args, code, exitError, stderr.String())
		}
		if stdout.Len() > 0 {
			t.Errorf("%v: stdout should be empty when nothing was listed:\n%s", args, stdout.String())
		}
		if !strings.Contains(stderr.String(), "connecting") || strings.Contains(stderr.String(), secret) {
			t.Errorf("%v: want a connection error without the password, stderr:\n%s", args, stderr.String())
		}
	}
}

// Value: protects=names that aren't valid UTF-8, such as a raw 8-bit CSI byte, are quoted rather than sent to the terminal; fails_when=printable only checks decoded runes, which turn bad bytes into a printable U+FFFD; why_new=only valid UTF-8 was tested; seam=none
func TestPrintable(t *testing.T) {
	tests := []struct{ in, want string }{
		{"shop_app", "shop_app"},
		{"smörgås", "smörgås"},
		{"a\x9bb", `"a\x9bb"`},
		{"a\xffb", `"a\xffb"`},
	}
	for _, tt := range tests {
		if got := printable(tt.in); got != tt.want {
			t.Errorf("printable(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

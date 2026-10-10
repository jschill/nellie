package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jschill/nellie/internal/pg"
)

// Value: protects=--dry-run prints the exact query and needs no connection, under both names; fails_when=the trumpet alias is dropped from dispatch, or the dry run connects or prompts; why_new=new code; seam=none
func TestListDryRun(t *testing.T) {
	clearConnEnv(t)
	for _, name := range []string{"list", "trumpet"} {
		t.Run(name, func(t *testing.T) {
			// Empty stdin: if it asked for the connection, it would fail.
			var stdout, stderr bytes.Buffer
			if code := Run([]string{name, "--dry-run"}, strings.NewReader(""), &stdout, &stderr); code != exitOK {
				t.Fatalf("exit code %d, stderr:\n%s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), pg.ListSQL+";\n") {
				t.Errorf("dry run doesn't print the query:\n%s", stdout.String())
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

// Value: protects=the human output lines up each project's users, marks expired roles, says when there are no users, and escapes names with control characters; fails_when=the layout changes, an empty note column adds trailing spaces, or a raw escape sequence reaches the terminal; why_new=new code; seam=none
func TestPrintList(t *testing.T) {
	var out bytes.Buffer
	printList(&out, []pg.ProjectInfo{
		{Name: "blog", Owner: "blog"},
		{Name: "shop", Owner: "alice", Users: []pg.UserInfo{
			{Name: "shop_admin", Kind: pg.AdminUser},
			{Name: "shop_app", Kind: pg.AppUser, Expired: true},
			{Name: "shop_\x1b[2J", Kind: pg.AppUser},
		}},
	})
	want := `blog  (owner blog)
  no users yet; add one with "nellie add-user"

shop  (owner alice)
  shop_admin      admin
  shop_app        application  VALID UNTIL has passed, so it can't log in
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

// Value: protects=the --json shape scripts rely on: field names, type names, and [] rather than null for no projects or no users; fails_when=a tag or a UserKind name changes, or a nil slice reaches the encoder; why_new=new code; seam=none
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
		}}}, `[{"project":"shop","owner":"shop","users":[` +
			`{"name":"shop_admin","type":"admin","expired":false},` +
			`{"name":"shop_app","type":"application","expired":true}]}]`},
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

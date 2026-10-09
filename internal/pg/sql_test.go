package pg

import (
	"strings"
	"testing"
)

// Value: protects=the quoting every SQL statement depends on: identifiers double their quotes, and string literals double single quotes; fails_when=a name or password with a quote breaks out of its SQL token; why_new=literal and ident have no direct test, only indirect dry-run substrings; seam=none
func TestLiteralAndIdentQuoting(t *testing.T) {
	tests := []struct {
		name, got, want string
	}{
		{"literal plain", literal("abc"), "'abc'"},
		{"literal doubles quote", literal("it's"), "'it''s'"},
		{"ident plain", ident("iba"), `"iba"`},
		{"ident doubles quote", ident(`a"b`), `"a""b"`},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %s, want %s", tt.name, tt.got, tt.want)
		}
	}
}

// Value: protects=new projects revoke every privilege from PUBLIC, including TEMPORARY, so application users can't create temp tables; fails_when=the revoke goes back to CONNECT only, and PUBLIC keeps TEMPORARY; why_new=the grant plan has no unit test; seam=none
func TestProjectPlanRevokesAllFromPublic(t *testing.T) {
	p, err := NewProject("iba")
	if err != nil {
		t.Fatal(err)
	}
	plan := p.Plan("SECRET-VERIFIER")
	var found bool
	for _, s := range plan.DBGrants {
		if s == `REVOKE ALL ON DATABASE "iba" FROM PUBLIC` {
			found = true
		}
		if strings.Contains(s, "REVOKE CONNECT") {
			t.Errorf("plan still revokes only CONNECT: %s", s)
		}
	}
	if !found {
		t.Errorf("no REVOKE ALL from PUBLIC in %v", plan.DBGrants)
	}
}

// Value: protects=servers older than Postgres 15 are refused before anything is created, because the grants depend on pg_database_owner; fails_when=the minimum is off by one or the check is skipped; why_new=checkServerVersion only runs against the test server's own version, so the boundary is never tested; seam=none
func TestCheckVersion(t *testing.T) {
	tests := []struct {
		version int
		ok      bool
	}{
		{140004, false},
		{150000, true},
		{150004, true},
		{180000, true},
	}
	for _, tt := range tests {
		if err := checkVersion(tt.version); (err == nil) != tt.ok {
			t.Errorf("checkVersion(%d) = %v, want ok=%v", tt.version, err, tt.ok)
		}
	}
}

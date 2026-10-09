package pg

import (
	"slices"
	"testing"
)

// Value: protects=the connection URL after a rotation points at the right project, also when project names contain underscores; fails_when=only the first or last underscore is tried, or the whole name (a project owner) is left out; why_new=new code; seam=none
func TestProjectCandidates(t *testing.T) {
	tests := []struct {
		role string
		want []string
	}{
		{"shop", []string{"shop"}},
		{"shop_app", []string{"shop_app", "shop"}},
		{"shop_v2_app", []string{"shop_v2_app", "shop_v2", "shop"}},
	}
	for _, tt := range tests {
		if got := projectCandidates(tt.role); !slices.Equal(got, tt.want) {
			t.Errorf("projectCandidates(%q) = %v, want %v", tt.role, got, tt.want)
		}
	}
}

// Value: protects=typed passwords that the client-side SCRAM verifier would hash differently from Postgres (non-ASCII, control characters) are refused; fails_when=the range check is off by one or skipped; why_new=new code; seam=none
func TestValidatePassword(t *testing.T) {
	tests := []struct {
		password string
		ok       bool
	}{
		{"", false},
		{"correct horse battery staple", true},
		{`!"#$%&'()*+,-./:;<=>?@[\]^_{|}~` + "`", true},
		{"tab\there", false},
		{"del\x7f", false},
		{"smörgåsbord", false},
	}
	for _, tt := range tests {
		if err := ValidatePassword(tt.password); (err == nil) != tt.ok {
			t.Errorf("ValidatePassword(%q) = %v, want ok=%v", tt.password, err, tt.ok)
		}
	}
}

// Value: protects=the role name and secret are quoted in the ALTER ROLE statement; fails_when=either is formatted in raw; why_new=new code; seam=none
func TestRotateSQL(t *testing.T) {
	// Value: protects=the suggested fix for an expired role is valid SQL for any accepted name, keywords included; fails_when=the role is printed unquoted (ALTER ROLE select ...); why_new=adversarial review; seam=none
	if got, want := ClearExpirySQL("select"), `ALTER ROLE "select" VALID UNTIL 'infinity'`; got != want {
		t.Errorf("ClearExpirySQL = %s, want %s", got, want)
	}
	got := RotateSQL("shop_app", "<redacted>")
	want := `ALTER ROLE "shop_app" PASSWORD '<redacted>'`
	if got != want {
		t.Errorf("RotateSQL = %s, want %s", got, want)
	}
}

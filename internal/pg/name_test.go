package pg

import (
	"strings"
	"testing"
)

func TestValidateProjectName(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"iba", true},
		{"my_project2", true},
		{"a", true},
		{strings.Repeat("a", MaxProjectNameLen), true},

		{"", false},
		{strings.Repeat("a", MaxProjectNameLen+1), false},
		{"Iba", false},        // would need quoting
		{"2fast", false},      // must start with a letter
		{"_iba", false},       // must start with a letter
		{"my-project", false}, // hyphen
		{"my project", false}, // space
		{"iba$", false},       // legal in Postgres, but not here
		{"åsa", false},        // non-ASCII
		{`iba"; DROP`, false}, // quoting tricks
		{"pg_stuff", false},   // reserved role prefix
		{"iba\n", false},      // regexp $ must not match before a trailing newline
	}
	for _, tt := range tests {
		err := ValidateProjectName(tt.name)
		if tt.valid && err != nil {
			t.Errorf("ValidateProjectName(%q) = %v, want nil", tt.name, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("ValidateProjectName(%q) = nil, want an error", tt.name)
		}
	}
}

func TestDefaultUserNameFits(t *testing.T) {
	project := strings.Repeat("a", MaxProjectNameLen)
	if err := ValidateUserName(project + DefaultUserSuffix); err != nil {
		t.Errorf("default user name for the longest project name: %v", err)
	}
}

func TestValidateUserName(t *testing.T) {
	if err := ValidateUserName(strings.Repeat("a", maxIdentifierLen)); err != nil {
		t.Errorf("63-character user name: %v", err)
	}
	for _, bad := range []string{"", strings.Repeat("a", maxIdentifierLen+1), "Bob", "pg_bob"} {
		if ValidateUserName(bad) == nil {
			t.Errorf("ValidateUserName(%q) = nil, want an error", bad)
		}
	}
}

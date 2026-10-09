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
		{"pg", false},         // its users would all start with pg_
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

func TestDefaultUserNamesFit(t *testing.T) {
	project := strings.Repeat("a", MaxProjectNameLen)
	for _, kind := range []UserKind{AppUser, AdminUser} {
		name := project + "_" + kind.DefaultSuffix()
		if err := ValidateUserName(name, project); err != nil {
			t.Errorf("default name for the longest project name: %v", err)
		}
	}
}

func TestValidateUserName(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"iba_app", true},
		{"iba_x", true},
		{"iba__x", true},
		{"iba_" + strings.Repeat("a", MaxNameLen-len("iba_")), true},

		{"iba_", false},     // nothing after the prefix
		{"iba", false},      // no prefix
		{"shop_app", false}, // another project's prefix
		{"ibaapp", false},
		{"iba_App", false},
		{"iba_" + strings.Repeat("a", MaxNameLen-len("iba_")+1), false},
	}
	for _, tt := range tests {
		err := ValidateUserName(tt.name, "iba")
		if tt.valid && err != nil {
			t.Errorf("ValidateUserName(%q) = %v, want nil", tt.name, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("ValidateUserName(%q) = nil, want an error", tt.name)
		}
	}
}

// Value: protects=rotate-password accepts any nellie-style role (owner or user, up to 63 chars) and rejects the rest before connecting; fails_when=the length limit or the pg_ rule is dropped, or owners need a <project>_ prefix; why_new=ValidateRoleName had no test of its own; seam=none
func TestValidateRoleName(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"shop", true},
		{"shop_v2_app", true},
		{strings.Repeat("a", MaxNameLen), true},

		{"", false},
		{strings.Repeat("a", MaxNameLen+1), false},
		{"pg_monitor", false},
		{"1shop", false},
		{"Shop", false},
	}
	for _, tt := range tests {
		if err := ValidateRoleName(tt.name); (err == nil) != tt.valid {
			t.Errorf("ValidateRoleName(%q) = %v, want valid=%v", tt.name, err, tt.valid)
		}
	}
}

package pgadmin

import (
	"strings"
	"testing"
)

func TestQuoteIdent(t *testing.T) {
	tests := map[string]string{
		"app":         `"app"`,
		"My App":      `"My App"`,
		`a"b`:         `"a""b"`,
		`x"; DROP --`: `"x""; DROP --"`,
		"åäö":         `"åäö"`,
	}
	for in, want := range tests {
		if got := QuoteIdent(in); got != want {
			t.Errorf("QuoteIdent(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestQuoteLiteral(t *testing.T) {
	tests := map[string]string{
		"secret":     `'secret'`,
		"it's":       `'it''s'`,
		`back\slash`: `E'back\\slash'`,
		`'\`:         `E'''\\'`,
	}
	for in, want := range tests {
		if got := QuoteLiteral(in); got != want {
			t.Errorf("QuoteLiteral(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestValidateName(t *testing.T) {
	if err := ValidateName("user", "alice"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := ValidateName("user", strings.Repeat("a", 63)); err != nil {
		t.Errorf("unexpected error for 63 byte name: %v", err)
	}
	for _, bad := range []string{"", "a\x00b", strings.Repeat("a", 64)} {
		if err := ValidateName("user", bad); err == nil {
			t.Errorf("ValidateName(%q) succeeded, want error", bad)
		}
	}
}

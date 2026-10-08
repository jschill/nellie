// Package pgadmin implements the PostgreSQL administration tasks used by the
// nellie CLI, such as managing projects (databases) and users (roles).
package pgadmin

import (
	"fmt"
	"strings"
)

// maxIdentifierLen is PostgreSQL's default NAMEDATALEN - 1. Longer names are
// silently truncated by the server, so they are rejected up front instead.
const maxIdentifierLen = 63

// ValidateName checks that name can be used as a PostgreSQL identifier.
func ValidateName(kind, name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%s name must not be empty", kind)
	case strings.ContainsRune(name, 0):
		return fmt.Errorf("%s name must not contain NUL characters", kind)
	case len(name) > maxIdentifierLen:
		return fmt.Errorf("%s name %q is longer than %d bytes", kind, name, maxIdentifierLen)
	}
	return nil
}

// QuoteIdent quotes name as a PostgreSQL identifier. Callers must validate
// name with ValidateName first.
func QuoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// QuoteLiteral quotes s as a PostgreSQL string literal. It works regardless
// of the server's standard_conforming_strings setting.
func QuoteLiteral(s string) string {
	s = strings.ReplaceAll(s, `'`, `''`)
	if strings.Contains(s, `\`) {
		return `E'` + strings.ReplaceAll(s, `\`, `\\`) + `'`
	}
	return `'` + s + `'`
}

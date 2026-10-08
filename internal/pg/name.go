package pg

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// maxIdentifierLen is Postgres's limit for database and role names (NAMEDATALEN - 1).
// Longer names aren't rejected by Postgres, they're silently truncated.
const maxIdentifierLen = 63

// MaxProjectNameLen leaves room for the suffix of the default user name
// (<project>_app), so that one always fits too.
const MaxProjectNameLen = maxIdentifierLen - len(DefaultUserSuffix)

// Lowercase only, so names never need quoting in SQL or psql. Postgres would
// also allow "$" and non-ASCII letters, but those are more trouble than
// they're worth in connection strings and shells.
var nameRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ValidateProjectName reports whether name can be used both as a database
// name and as the name of the role that owns it.
func ValidateProjectName(name string) error {
	return validateName("project", name, MaxProjectNameLen)
}

// ValidateUserName reports whether name can be used as a role name.
func ValidateUserName(name string) error {
	return validateName("user", name, maxIdentifierLen)
}

func validateName(kind, name string, maxLen int) error {
	switch {
	case name == "":
		return fmt.Errorf("%s name is empty", kind)
	case len(name) > maxLen:
		return fmt.Errorf("%s name is %d characters long; the maximum is %d", kind, len(name), maxLen)
	case !nameRe.MatchString(name):
		return fmt.Errorf("%s name must start with a lowercase letter (a-z) and contain only lowercase letters, digits and underscores", kind)
	case strings.HasPrefix(name, "pg_"):
		return errors.New(`names can't start with "pg_": Postgres reserves that prefix for role names`)
	}
	return nil
}

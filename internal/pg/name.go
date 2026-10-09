package pg

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// MaxNameLen is Postgres's limit for database and role names (NAMEDATALEN - 1).
// Longer names aren't rejected by Postgres, they're silently truncated.
const MaxNameLen = 63

// MaxProjectNameLen leaves room for the longest default user name
// (<project>_admin), so the suggested names always fit.
const MaxProjectNameLen = MaxNameLen - len("_"+adminSuffix)

// Lowercase only, so names never need quoting in SQL or psql. Postgres would
// also allow "$" and non-ASCII letters, but those are more trouble than
// they're worth in connection strings and shells.
var nameRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ValidateProjectName reports whether name can be used both as a database
// name and as the name of the role that owns it.
func ValidateProjectName(name string) error {
	if err := validateName("project", name, MaxProjectNameLen); err != nil {
		return err
	}
	// Every user is named <project>_<suffix>, and role names can't start with pg_.
	if name == "pg" {
		return errors.New(`project name can't be "pg": its users would be named pg_..., which Postgres reserves`)
	}
	return nil
}

// ValidateUserName reports whether name can be used as the name of a user in
// project: a valid role name that starts with "<project>_".
func ValidateUserName(name, project string) error {
	if err := validateName("user", name, MaxNameLen); err != nil {
		return err
	}
	prefix := project + "_"
	if !strings.HasPrefix(name, prefix) || len(name) == len(prefix) {
		return fmt.Errorf("user name must be %s followed by at least one character", prefix)
	}
	return nil
}

// IsNameChar reports whether c may appear in a name after its first character.
func IsNameChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
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

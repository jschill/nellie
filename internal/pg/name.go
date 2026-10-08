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

// MaxProjectNameLen leaves room for the longest role suffix, so that every
// role nellie derives from a project name is still a valid identifier.
const MaxProjectNameLen = maxIdentifierLen - len(ownerSuffix)

// Lowercase only, so the name never needs quoting in SQL or psql. Postgres
// would also allow "$" and non-ASCII letters, but those are more trouble than
// they're worth in connection strings and shells.
var projectNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ValidateProjectName reports whether name can be used both as a database
// name and as the base for the project's role names.
func ValidateProjectName(name string) error {
	switch {
	case name == "":
		return errors.New("project name is empty")
	case len(name) > MaxProjectNameLen:
		return fmt.Errorf("project name is %d characters long; the maximum is %d", len(name), MaxProjectNameLen)
	case !projectNameRe.MatchString(name):
		return errors.New("project name must start with a lowercase letter (a-z) and contain only lowercase letters, digits and underscores")
	case strings.HasPrefix(name, "pg_"):
		return errors.New(`project name can't start with "pg_": Postgres reserves that prefix for role names`)
	}
	return nil
}

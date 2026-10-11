package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

// loadDotenv sets DATABASE_URL from a .env-style file, like Node's dotenv. A
// DATABASE_URL that's already set wins, so a one-off
// `DATABASE_URL=... nellie add-project` still overrides the file. A missing
// file isn't an error.
//
// Every other key is skipped with a warning that names it. A .env in a
// checked-out repo isn't trusted: PG* keys could point nellie at another
// host while the admin password is in the environment, and keys like
// GODEBUG or SSL_CERT_FILE change how Go resolves names and checks TLS. For
// the same reason a DATABASE_URL from the file must carry its own password,
// and can't sit next to PG* settings from the shell (see connConfig).
func loadDotenv(path string, warn io.Writer) error {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	vars, err := parseDotenv(f)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for _, v := range vars {
		if v.key != "DATABASE_URL" {
			fmt.Fprintf(warn, "nellie: ignoring %s in .env, which only sets DATABASE_URL; set it in your shell instead\n", printable(v.key))
			continue
		}
		if _, set := os.LookupEnv(v.key); !set {
			os.Setenv(v.key, v.value)
			fromDotenv[v.key] = true
		}
	}
	return nil
}

// fromDotenv records the keys loadDotenv set in this process, so connConfig
// can tell a DATABASE_URL from a checked-out .env from one the user exported.
var fromDotenv = map[string]bool{}

type envVar struct{ key, value string }

// parseDotenv reads KEY=value lines. It understands blank lines, # comments,
// an optional "export " prefix, and values in single or double quotes. There
// are no escape sequences or ${VAR} expansion.
func parseDotenv(r io.Reader) ([]envVar, error) {
	var vars []envVar
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if n == 1 {
			// Some editors start the file with a byte order mark, which
			// TrimSpace keeps; it would end up in the first key.
			line = strings.TrimPrefix(line, "\ufeff")
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" || strings.ContainsAny(key, " \t") {
			// Don't quote the line: it may well contain a password.
			return nil, fmt.Errorf("line %d: want KEY=value", n)
		}
		value, err := unquote(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		vars = append(vars, envVar{key, value})
	}
	return vars, sc.Err()
}

func unquote(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if q := v[0]; q == '"' || q == '\'' {
		end := strings.IndexByte(v[1:], q)
		if end < 0 {
			return "", errors.New("missing closing quote")
		}
		if rest := strings.TrimSpace(v[end+2:]); rest != "" && !strings.HasPrefix(rest, "#") {
			return "", errors.New("unexpected text after closing quote")
		}
		return v[1 : end+1], nil
	}
	// Unquoted: " #" starts a comment. A "#" without a space before it is
	// part of the value.
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return v, nil
}

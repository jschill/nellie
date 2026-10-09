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

// loadDotenv sets environment variables from a .env-style file, like Node's
// dotenv. Variables that are already set win, so a one-off
// `DATABASE_URL=... nellie add-project` still overrides the file. A missing
// file isn't an error.
//
// Connection-target keys (PG*) and TLS trust keys (SSL_CERT_*) are never taken
// from the file: a .env in a checked-out repo could otherwise point nellie at
// another host while the admin password is in the environment. They're skipped
// with a warning that names the key. Set them in your shell instead.
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
		if fileMayNotSet(v.key) {
			fmt.Fprintf(warn, "nellie: ignoring %s in .env; set it in your shell instead\n", v.key)
			continue
		}
		if _, set := os.LookupEnv(v.key); !set {
			os.Setenv(v.key, v.value)
		}
	}
	return nil
}

// fileMayNotSet reports whether key must come from the environment, not .env.
func fileMayNotSet(key string) bool {
	return strings.HasPrefix(key, "PG") || strings.HasPrefix(key, "SSL_CERT_")
}

type envVar struct{ key, value string }

// parseDotenv reads KEY=value lines. It understands blank lines, # comments,
// an optional "export " prefix, and values in single or double quotes. There
// are no escape sequences or ${VAR} expansion.
func parseDotenv(r io.Reader) ([]envVar, error) {
	var vars []envVar
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
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

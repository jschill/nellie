package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseDotenv(t *testing.T) {
	input := `
# a comment
DATABASE_URL=postgres://admin:pw@localhost:5432/postgres
export PGUSER=admin
SPACED = value with spaces   # trailing comment
HASH=pa#ss
DOUBLE="quoted # not a comment"
SINGLE='single quoted' # comment
EMPTY=
`
	got, err := parseDotenv(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	want := []envVar{
		{"DATABASE_URL", "postgres://admin:pw@localhost:5432/postgres"},
		{"PGUSER", "admin"},
		{"SPACED", "value with spaces"},
		{"HASH", "pa#ss"},
		{"DOUBLE", "quoted # not a comment"},
		{"SINGLE", "single quoted"},
		{"EMPTY", ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestParseDotenvErrorsHideTheLine(t *testing.T) {
	for _, input := range []string{
		"no equals sign secret",
		"=secret",
		"TWO WORDS=secret",
		`OPEN="secret`,
		`AFTER='sec''ret'`, // no escapes, so this isn't one value
	} {
		_, err := parseDotenv(strings.NewReader(input))
		if err == nil {
			t.Errorf("parseDotenv(%q) succeeded, want an error", input)
			continue
		}
		if strings.Contains(err.Error(), "secret") {
			t.Errorf("error for %q leaks the line: %v", input, err)
		}
	}
}

func TestLoadDotenvKeepsExistingVars(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("NELLIE_TEST_SET=from-file\nNELLIE_TEST_UNSET=from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NELLIE_TEST_SET", "from-shell")
	t.Setenv("NELLIE_TEST_UNSET", "") // registers cleanup for the next line
	os.Unsetenv("NELLIE_TEST_UNSET")

	if err := loadDotenv(path, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("NELLIE_TEST_SET"); got != "from-shell" {
		t.Errorf("NELLIE_TEST_SET = %q, want the shell's value", got)
	}
	if got := os.Getenv("NELLIE_TEST_UNSET"); got != "from-file" {
		t.Errorf("NELLIE_TEST_UNSET = %q, want the file's value", got)
	}
}

func TestLoadDotenvMissingFile(t *testing.T) {
	if err := loadDotenv(filepath.Join(t.TempDir(), "nope"), io.Discard); err != nil {
		t.Errorf("missing file: %v", err)
	}
}

// Value: protects=PG* connection settings and SSL trust settings are never taken from .env, so a checked-out .env can't redirect the admin connection; fails_when=PGHOST or SSL_CERT_FILE from the file gets set, or the warning doesn't name the key; why_new=the .env allow-list has no test; seam=none
func TestLoadDotenvIgnoresConnectionKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("PGHOST=attacker.example\nSSL_CERT_FILE=/tmp/evil.pem\nNELLIE_TEST_ALLOWED=ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"PGHOST", "SSL_CERT_FILE", "NELLIE_TEST_ALLOWED"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}

	var warn bytes.Buffer
	if err := loadDotenv(path, &warn); err != nil {
		t.Fatal(err)
	}
	if _, set := os.LookupEnv("PGHOST"); set {
		t.Error("PGHOST was set from .env")
	}
	if _, set := os.LookupEnv("SSL_CERT_FILE"); set {
		t.Error("SSL_CERT_FILE was set from .env")
	}
	if os.Getenv("NELLIE_TEST_ALLOWED") != "ok" {
		t.Error("an ordinary key from .env should still be loaded")
	}
	for _, k := range []string{"PGHOST", "SSL_CERT_FILE"} {
		if !strings.Contains(warn.String(), k) {
			t.Errorf("no warning naming %s:\n%s", k, warn.String())
		}
	}
	if strings.Contains(warn.String(), "attacker.example") {
		t.Errorf("the warning echoes a value:\n%s", warn.String())
	}
}

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

// Value: protects=a .env saved with a byte order mark still sets its first key; fails_when=the BOM strip goes, so the key becomes "\ufeffDATABASE_URL" and nellie silently asks instead; why_new=adversarial review; seam=none
func TestParseDotenvSkipsByteOrderMark(t *testing.T) {
	got, err := parseDotenv(strings.NewReader("\ufeffDATABASE_URL=postgres://localhost/postgres\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].key != "DATABASE_URL" {
		t.Errorf("got %q, want the key DATABASE_URL", got)
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
	if err := os.WriteFile(path, []byte("DATABASE_URL=postgres://from-file/postgres\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := fromDotenv
	t.Cleanup(func() { fromDotenv = saved })

	fromDotenv = map[string]bool{}
	t.Setenv("DATABASE_URL", "postgres://from-shell/postgres")
	if err := loadDotenv(path, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("DATABASE_URL"); got != "postgres://from-shell/postgres" || fromDotenv["DATABASE_URL"] {
		t.Errorf("DATABASE_URL = %q (from .env: %v), want the shell's value", got, fromDotenv["DATABASE_URL"])
	}

	os.Unsetenv("DATABASE_URL") // t.Setenv above restores it afterwards
	if err := loadDotenv(path, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("DATABASE_URL"); got != "postgres://from-file/postgres" || !fromDotenv["DATABASE_URL"] {
		t.Errorf("DATABASE_URL = %q (from .env: %v), want the file's value", got, fromDotenv["DATABASE_URL"])
	}
}

func TestLoadDotenvMissingFile(t *testing.T) {
	if err := loadDotenv(filepath.Join(t.TempDir(), "nope"), io.Discard); err != nil {
		t.Errorf("missing file: %v", err)
	}
}

// Value: protects=.env only ever sets DATABASE_URL, so a checked-out .env can't redirect the admin connection or change Go's TLS and DNS behavior; fails_when=PGHOST, SSL_CERT_FILE, GODEBUG or any other key from the file gets set, or the warning doesn't name it; why_new=adversarial review: GODEBUG and resolver keys got through the old block list; seam=none
func TestLoadDotenvOnlySetsDatabaseURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("PGHOST=attacker.example\nSSL_CERT_FILE=/tmp/evil.pem\nGODEBUG=tlsrsakex=1\nNELLIE_TEST_OTHER=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ignored := []string{"PGHOST", "SSL_CERT_FILE", "GODEBUG", "NELLIE_TEST_OTHER"}
	for _, k := range ignored {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}

	var warn bytes.Buffer
	if err := loadDotenv(path, &warn); err != nil {
		t.Fatal(err)
	}
	for _, k := range ignored {
		if _, set := os.LookupEnv(k); set {
			t.Errorf("%s was set from .env", k)
		}
		if !strings.Contains(warn.String(), k) {
			t.Errorf("no warning naming %s:\n%s", k, warn.String())
		}
	}
	if strings.Contains(warn.String(), "attacker.example") {
		t.Errorf("the warning echoes a value:\n%s", warn.String())
	}
}

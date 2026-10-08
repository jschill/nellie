package cli

import (
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

	if err := loadDotenv(path); err != nil {
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
	if err := loadDotenv(filepath.Join(t.TempDir(), "nope")); err != nil {
		t.Errorf("missing file: %v", err)
	}
}

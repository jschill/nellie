package cli

import (
	"bytes"
	"strings"
	"testing"
)

// clearConnEnv unsets everything connConfig looks at, for this test only.
func clearConnEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{"DATABASE_URL", "PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGSERVICE"} {
		t.Setenv(v, "")
	}
}

func TestDryRunRetriesInvalidNames(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"add-project", "--dry-run"}, strings.NewReader("Bad-Name\niba\n"), &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit code %d, stderr:\n%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "must start with a lowercase letter") {
		t.Errorf("expected a validation error for Bad-Name, stderr:\n%s", stderr.String())
	}
	if !strings.Contains(stdout.String(), `CREATE DATABASE "iba" OWNER "iba_owner"`) {
		t.Errorf("unexpected dry-run output:\n%s", stdout.String())
	}
}

func TestConnConfigPrompts(t *testing.T) {
	clearConnEnv(t)
	// The URL and the project name come from the same stdin, so this also
	// checks that the first prompt doesn't swallow the second answer.
	var out bytes.Buffer
	p := newPrompter(strings.NewReader("not a url ::\npostgres://admin:secret@db.example:6543/postgres\niba\n"), &out)

	cfg, err := connConfig("", p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "db.example" || cfg.Port != 6543 || cfg.User != "admin" {
		t.Errorf("got host=%s port=%d user=%s", cfg.Host, cfg.Port, cfg.User)
	}
	if strings.Contains(out.String(), "secret") {
		t.Errorf("password leaked into prompt output:\n%s", out.String())
	}

	project, err := promptProject(p)
	if err != nil {
		t.Fatal(err)
	}
	if project.Name != "iba" {
		t.Errorf("project name = %q, want iba", project.Name)
	}
}

func TestConnConfigDoesNotPromptWhenConfigured(t *testing.T) {
	clearConnEnv(t)
	t.Setenv("DATABASE_URL", "postgres://admin@envhost/postgres")
	p := newPrompter(strings.NewReader(""), &bytes.Buffer{}) // any read would fail

	cfg, err := connConfig("", p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "envhost" {
		t.Errorf("host = %s, want envhost from DATABASE_URL", cfg.Host)
	}

	cfg, err = connConfig("postgres://admin@flaghost/postgres", p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "flaghost" {
		t.Errorf("host = %s, want flaghost from --dsn", cfg.Host)
	}
}

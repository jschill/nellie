package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/jschill/nellie/internal/pg"
)

// clearConnEnv unsets everything connConfig looks at, for this test only.
func clearConnEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{"DATABASE_URL", "PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGSERVICE", "PGSSLMODE"} {
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
	if !strings.Contains(stdout.String(), `CREATE DATABASE "iba" OWNER "iba"`) {
		t.Errorf("unexpected dry-run output:\n%s", stdout.String())
	}
}

func TestConnConfigPrompts(t *testing.T) {
	clearConnEnv(t)
	// The URL and the project name come from the same stdin, so this also
	// checks that the first prompt doesn't swallow the second answer.
	var out bytes.Buffer
	p := newPrompter(strings.NewReader("not a url ::\npostgres://admin:secret@db.example:6543/postgres\niba\n"), &out)

	cfg, err := connConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "db.example" || cfg.Port != 6543 || cfg.User != "admin" {
		t.Errorf("got host=%s port=%d user=%s", cfg.Host, cfg.Port, cfg.User)
	}
	if mode := sslModeOf(cfg); mode != "require" {
		t.Errorf("sslmode = %q, want require by default", mode)
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

	cfg, err := connConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "envhost" {
		t.Errorf("host = %s, want envhost from DATABASE_URL", cfg.Host)
	}

	// Any libpq variable counts as configured, not only DATABASE_URL.
	clearConnEnv(t)
	t.Setenv("PGHOST", "pghost")
	cfg, err = connConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "pghost" {
		t.Errorf("host = %s, want pghost from PGHOST", cfg.Host)
	}
}

func TestAddUserDryRunDefaults(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// Project, then Enter for the default type and the default name.
	code := Run([]string{"add-user", "--dry-run"}, strings.NewReader("iba\n\n\n"), &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit code %d, stderr:\n%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "User name: iba_ [app]: ") {
		t.Errorf("default name not offered, stderr:\n%s", stderr.String())
	}
	for _, want := range []string{
		`CREATE ROLE "iba_app" LOGIN`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "iba_app"`,
		`ALTER DEFAULT PRIVILEGES FOR ROLE "iba" IN SCHEMA public`,
		"\\connect iba\n",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("dry-run output lacks %q:\n%s", want, stdout.String())
		}
	}
}

func TestAddUserDryRunAdmin(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// An unknown type and a bad name are asked again.
	input := "iba\nroot\nadmin\nOps!\nops\n"
	code := Run([]string{"add-user", "--dry-run"}, strings.NewReader(input), &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit code %d, stderr:\n%s", code, stderr.String())
	}
	for _, want := range []string{"answer one of: app, admin", `'O' isn't allowed`} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr.String())
		}
	}
	for _, want := range []string{
		`CREATE ROLE "iba_ops" LOGIN`,
		`GRANT "iba" TO "iba_ops"`,
		`ALTER ROLE "iba_ops" IN DATABASE "iba" SET role TO "iba"`,
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("dry-run output lacks %q:\n%s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), `\connect`) {
		t.Errorf("admin users need no schema grants:\n%s", stdout.String())
	}
}

// Value: protects=the connection URL that add-project and add-user print, which is the only way the user gets to connect; fails_when=a TCP host or port, IPv6 brackets, a Unix socket directory or its port, or the sslmode come out wrong, so the URL parses back to different settings than the admin connection; why_new=connURL has no test at all; seam=none
func TestConnURL(t *testing.T) {
	clearConnEnv(t)
	const password = "PASSWORD2345"
	tests := []struct {
		name string
		dsn  string
	}{
		{"host and port", "postgres://admin@db.example:6543/postgres"},
		{"default port", "postgres://admin@db.example/postgres"},
		{"IPv6 address", "postgres://admin@[::1]:5432/postgres"},
		{"Unix socket directory", "postgres://admin@/postgres?host=/var/run/postgresql"},
		{"Unix socket, non-default port", "postgres://admin@/postgres?host=/var/run/postgresql&port=5433"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			admin, err := parseAdmin(tt.dsn)
			if err != nil {
				t.Fatal(err)
			}
			printed := connURL(admin, "iba", password, "iba")
			// Parse the printed URL back, the way a client would.
			got, err := pgx.ParseConfig(printed)
			if err != nil {
				t.Fatalf("connURL output doesn't parse: %v", err)
			}
			if got.Host != admin.Host || got.Port != admin.Port {
				t.Errorf("host:port = %s:%d, want %s:%d", got.Host, got.Port, admin.Host, admin.Port)
			}
			if got.User != "iba" || got.Database != "iba" {
				t.Errorf("user = %s, database = %s; want iba and iba", got.User, got.Database)
			}
			if got.Password != password {
				t.Errorf("password doesn't round-trip through the URL")
			}
			if strings.HasPrefix(admin.Host, "/") {
				if strings.Contains(printed, "sslmode") {
					t.Errorf("socket URL should not carry sslmode: %s", printed)
				}
			} else if !strings.Contains(printed, "sslmode="+sslModeOf(admin)) {
				t.Errorf("URL lacks the admin's sslmode %q: %s", sslModeOf(admin), printed)
			}
		})
	}
}

// Value: protects=the key decoding that the arrow-key menu and the prefixed name field depend on (arrows, Enter, backspace, Ctrl-U, Ctrl-C, pasted text); fails_when=an escape sequence or control byte is misread, so an arrow types letters or Ctrl-C stops interrupting; why_new=readKeys has no test and otherwise runs only on a real terminal; seam=none (reads from the existing tty field, backed by an os.Pipe)
func TestReadKeys(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []keyPress
	}{
		{"up and down arrows", "\x1b[A\x1b[B", []keyPress{{key: keyUp}, {key: keyDown}}},
		{"Enter as CR or LF", "\r\n", []keyPress{{key: keyEnter}, {key: keyEnter}}},
		{"backspace as DEL or BS", "\x7f\x08", []keyPress{{key: keyBackspace}, {key: keyBackspace}}},
		{"Ctrl-U clears", "\x15", []keyPress{{key: keyClear}}},
		{"Ctrl-C and Ctrl-D interrupt", "\x03\x04", []keyPress{{key: keyInterrupt}, {key: keyInterrupt}}},
		{"printable characters in order", "ab", []keyPress{{key: keyText, ch: 'a'}, {key: keyText, ch: 'b'}}},
		{"pasted text with a key", "x\r", []keyPress{{key: keyText, ch: 'x'}, {key: keyEnter}}},
		{"unsupported escape sequence is consumed whole", "\x1b[Cq", []keyPress{{key: keyText, ch: 'q'}}},
		{"Ctrl-Up with a modifier is up, not typed text", "\x1b[1;5A", []keyPress{{key: keyUp}}},
		{"incomplete escape sequence at the end of a read is dropped", "\x1b[", nil},
		{"incomplete sequence with parameters is dropped", "\x1b[1;5", nil},
		{"ESC [ then Enter keeps the Enter", "\x1b[\r", []keyPress{{key: keyEnter}}},
		{"ESC [ then Ctrl-C keeps the interrupt", "\x1b[\x03", []keyPress{{key: keyInterrupt}}},
		{"control character is other", "\t", []keyPress{{key: keyOther}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if _, err := w.WriteString(tt.input); err != nil {
				t.Fatal(err)
			}
			w.Close()

			p := &prompter{tty: r, fd: -1}
			got, err := p.readKeys()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("readKeys(%q) = %+v, want %+v", tt.input, got, tt.want)
			}
		})
	}
}

// Value: protects=the exit code contract for usage errors (no command, unknown command, extra argument) is 2 and nothing is prompted for; fails_when=a usage error exits 0 or 1 or starts asking questions; why_new=no test checks the exit codes of Run, only the commands' own paths; seam=none
func TestUsageErrorsExitTwo(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string // a substring of stderr
	}{
		{"no command", nil, "Usage: nellie <command>"},
		{"unknown command", []string{"bogus"}, `unknown command "bogus"`},
		{"extra argument", []string{"add-project", "extra"}, "takes no arguments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Empty stdin: if the command prompts, it fails with "no ... given"
			// and the exit code would be 1, not 2.
			var stdout, stderr bytes.Buffer
			code := Run(tt.args, strings.NewReader(""), &stdout, &stderr)
			if code != exitUsage {
				t.Errorf("exit code = %d, want %d; stderr:\n%s", code, exitUsage, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("stderr lacks %q:\n%s", tt.want, stderr.String())
			}
		})
	}
}

// Value: protects=a malformed .env stops nellie before any command runs or prompts, and its error names the line number without echoing it; fails_when=Run ignores the .env error or continues into the command; why_new=loadDotenv errors are tested in isolation, not through Run; seam=none
func TestMalformedDotenvStopsBeforeCommand(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile(".env", []byte("DATABASE_URL=postgres://ok\nthis line has no equals sign\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"add-project", "--dry-run"}, strings.NewReader("iba\n"), &stdout, &stderr)
	if code != exitError {
		t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "reading .env") || !strings.Contains(stderr.String(), "line 2") {
		t.Errorf("error should name the .env line:\n%s", stderr.String())
	}
	if strings.Contains(stderr.String(), "no equals sign") {
		t.Errorf("error echoes the line, which may hold a password:\n%s", stderr.String())
	}
	if strings.Contains(stderr.String(), "Project name") || stdout.Len() > 0 {
		t.Errorf("command ran despite the .env error; stdout:\n%s", stdout.String())
	}
}

// Value: protects=the admin connection never falls back to plaintext: TLS is required by default, prefer and empty sslmode behave like require, sslmode=disable is honored only when asked for, and sslmode=allow is refused; fails_when=a TCP connection can reach a plaintext attempt, or a service-file or duplicate-key setting is misread; why_new=the TLS policy has no test, and a regression would send the admin password unencrypted; seam=none
func TestAdminTLSPolicy(t *testing.T) {
	tests := []struct {
		name string
		env  string // PGSSLMODE
		dsn  string
		want string // sslModeOf for the resolved config; "" means the socket case
	}{
		{"default is require", "", "postgres://admin@db.example/postgres", "require"},
		{"prefer is treated as require", "", "postgres://admin@db.example/postgres?sslmode=prefer", "require"},
		{"empty sslmode is treated as require", "", "postgres://admin@db.example/postgres?sslmode=", "require"},
		{"PGSSLMODE prefer is treated as require", "prefer", "postgres://admin@db.example/postgres", "require"},
		{"explicit disable is honored", "", "postgres://admin@db.example/postgres?sslmode=disable", "disable"},
		{"keyword form, verify-full", "", "host=db.example user=admin sslmode=verify-full", "verify-full"},
		{"keyword form with spaces around =", "", "host=db.example user=admin sslmode = verify-full", "verify-full"},
		{"verify-ca is not confused with require", "", "postgres://admin@db.example/postgres?sslmode=verify-ca", "verify-ca"},
		{"multi-host disable has no TLS", "", "postgres://admin@db1.example,db2.example/postgres?sslmode=disable", "disable"},
		{"Unix socket is left alone", "", "postgres://admin@/postgres?host=/var/run/postgresql", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearConnEnv(t)
			t.Setenv("PGSSLMODE", tt.env)
			cfg, err := parseAdmin(tt.dsn)
			if err != nil {
				t.Fatal(err)
			}
			if tt.want == "" {
				if !allUnixSockets(cfg) {
					t.Errorf("expected a socket connection, host %s", cfg.Host)
				}
				return
			}
			if got := sslModeOf(cfg); got != tt.want {
				t.Errorf("sslmode = %q, want %q", got, tt.want)
			}
			for _, fb := range cfg.Fallbacks {
				if fb.TLSConfig == nil && cfg.TLSConfig != nil {
					t.Errorf("plaintext fallback to %s survived; the connection can downgrade", fb.Host)
				}
			}
		})
	}
}

func TestAdminTLSRefusesAllow(t *testing.T) {
	clearConnEnv(t)
	if _, err := parseAdmin("postgres://admin@db.example/postgres?sslmode=allow"); err == nil {
		t.Error("sslmode=allow was accepted; it tries plaintext first")
	}
}

// Value: protects=a connection string pgx can't parse never has its text echoed, so a password typed at the prompt can't reach the terminal or the log; fails_when=the error from pgx is printed, which can contain the password; why_new=the redaction is only pgx's best effort and has been shown to miss keyword forms; seam=none
func TestBadURLDoesNotEchoPassword(t *testing.T) {
	clearConnEnv(t)
	const secret = "S3cr3tPW"
	var out bytes.Buffer
	p := newPrompter(strings.NewReader("host=db.example PASSWORD="+secret+" sslmode=bogus\npostgres://admin:"+secret+"@db.example/postgres\n"), &out)
	if _, err := connConfig(p); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), secret) {
		t.Errorf("password echoed while retrying:\n%s", out.String())
	}
}

// Value: protects=the line-mode name prompt refuses a name that would exceed Postgres's limit, and asks again instead of accepting it; fails_when=a 64-character name is accepted or the prompt returns without a second answer; why_new=the raw-mode length check has no test and the line fallback is the only testable path; seam=none
func TestPrefixedLineLengthLimit(t *testing.T) {
	tooLong := strings.Repeat("a", 60) // "iba_" + 60 is 64 characters, over the limit
	ok := strings.Repeat("a", 59)      // "iba_" + 59 is 63, exactly the limit
	var out bytes.Buffer
	p := newPrompter(strings.NewReader(tooLong+"\n"+ok+"\n"), &out)

	got, err := p.prefixed("User name", "iba_", "", pg.MaxNameLen, pg.IsNameChar)
	if err != nil {
		t.Fatal(err)
	}
	if got != "iba_"+ok {
		t.Errorf("got %q, want the second answer", got)
	}
	if !strings.Contains(out.String(), "is 64 characters long; the maximum is 63") {
		t.Errorf("no length error printed:\n%s", out.String())
	}
}

// Value: protects=flag errors give exit 2 and -h gives exit 0, so scripts can tell a mistake from a request for help; fails_when=an unknown flag exits 0 or 1, or -h exits with an error; why_new=parseFlags' early returns have no test, and only command-level usage errors are covered; seam=none
func TestFlagErrorExitCodes(t *testing.T) {
	tests := []struct {
		args []string
		want int
	}{
		{[]string{"add-project", "--bogus"}, exitUsage},
		{[]string{"add-project", "-h"}, exitOK},
	}
	for _, tt := range tests {
		var stdout, stderr bytes.Buffer
		if code := Run(tt.args, strings.NewReader(""), &stdout, &stderr); code != tt.want {
			t.Errorf("%v: exit %d, want %d; stderr:\n%s", tt.args, code, tt.want, stderr.String())
		}
	}
}

// Value: protects=the exit-code contract of fail (130 for an interrupt, 1 otherwise) and that a failed cleanup after Ctrl-C still says what was left behind; fails_when=a cancelled context hides the "may be left behind" message or exits 1; why_new=fail had no test and the interrupt path was the one that swallowed the cleanup error; seam=none
func TestFailExitCodes(t *testing.T) {
	cleanup := fmt.Errorf("%w, role x may be left behind: %w", pg.ErrCleanupFailed, errors.New("connection refused"))
	tests := []struct {
		name       string
		err        error
		wantCode   int
		wantStderr string
	}{
		{"prompt interrupt", errInterrupted, exitInterrupted, "nellie: interrupted\n"},
		{"cancelled context", fmt.Errorf("creating role: %w", context.Canceled), exitInterrupted, "nellie: interrupted\n"},
		{"interrupt and failed cleanup", errors.Join(context.Canceled, cleanup), exitInterrupted, "nellie: interrupted: "},
		{"plain error", errors.New("boom"), exitError, "nellie: boom\n"},
		{"failed cleanup without interrupt", cleanup, exitError, "may be left behind"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			if code := fail(&stderr, tt.err); code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

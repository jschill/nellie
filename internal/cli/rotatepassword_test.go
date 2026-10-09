package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Value: protects=rotate-password --dry-run prints the redacted ALTER ROLE for the user argument and never asks for a password; fails_when=the dry run prompts for a password, connects, or leaks a real secret; why_new=new command; seam=none
func TestRotatePasswordDryRun(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		stdin string
	}{
		{"argument", []string{"rotate-password", "--dry-run", "shop_app"}, ""}, // empty stdin: any prompt would fail
		{"argument, piped password ignored", []string{"rotate-password", "shop_app", "--dry-run"}, "not read\n"},
	}
	want := dryRunNote + `ALTER ROLE "shop_app" PASSWORD '<redacted>';` + "\n"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(tt.args, strings.NewReader(tt.stdin), &stdout, &stderr)
			if code != exitOK {
				t.Fatalf("exit code %d, stderr:\n%s", code, stderr.String())
			}
			if stdout.String() != want {
				t.Errorf("stdout = %q, want %q", stdout.String(), want)
			}
			if strings.Contains(stderr.String(), "password") {
				t.Errorf("dry run asked for a password:\n%s", stderr.String())
			}
		})
	}
}

// Value: protects=bad command lines for rotate-password exit 2 before anything is asked or connected; fails_when=a second argument is ignored, or an invalid name only fails later with exit 1; why_new=parseFlags gained optional arguments; seam=none
func TestRotatePasswordUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"two users", []string{"rotate-password", "a_app", "b_app"}, "too many arguments"},
		{"bad name", []string{"rotate-password", "Shop"}, "must start with a lowercase letter"},
		{"reserved prefix", []string{"rotate-password", "pg_monitor"}, `can't start with "pg_"`},
		{"json with dry-run", []string{"rotate-password", "--dry-run", "--json", "shop_app"}, "can't be combined"},
		// Value: protects=piped input is only ever the password: without a user argument it is refused, so a dry run can't print a piped password as the role name; fails_when=the user is prompted from the pipe again; why_new=QA found the dry run leaking a piped passphrase; seam=none
		{"piped, no user", []string{"rotate-password", "--dry-run"}, "give the user as an argument"},
		// Value: protects=a piped password never reaches the admin-URL prompt; fails_when=connConfig prompts on a pipe again and swallows the password; why_new=QA found the documented pipe failing without DATABASE_URL; seam=none
		{"piped, no admin URL", []string{"rotate-password", "shop_app"}, "set DATABASE_URL"},
	}
	clearConnEnv(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(tt.args, strings.NewReader(""), &stdout, &stderr); code != exitUsage {
				t.Errorf("exit code = %d, want %d; stderr:\n%s", code, exitUsage, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("stderr lacks %q:\n%s", tt.want, stderr.String())
			}
		})
	}
}

// Value: protects=the piped password path: a typed password is kept byte for byte (spaces too), and an empty, missing, multi-line or bad pipe fails instead of generating or guessing; fails_when=EOF or an empty line is treated as "generate", the password is trimmed, or a bad pipe loops; why_new=new prompt; seam=none
func TestPromptNewPassword(t *testing.T) {
	tests := []struct {
		name         string
		stdin        string
		wantPassword string
		wantErr      string
		wantWarning  bool
	}{
		// Value: protects=an empty piped line (an unset variable in echo "$PW") is refused instead of rotating to a random password; fails_when=empty piped input generates again; why_new=pass-3 red team; seam=none
		{name: "empty line", stdin: "\n", wantErr: "piped line is empty"},
		{name: "typed", stdin: "correct horse battery\n", wantPassword: "correct horse battery"},
		{name: "spaces kept", stdin: "  padded password  \n", wantPassword: "  padded password  "},
		{name: "short warns", stdin: "hunter2\n", wantPassword: "hunter2", wantWarning: true},
		{name: "end of input", stdin: "", wantErr: "no password given"},
		{name: "not ASCII", stdin: "smörgåsbord-smörgåsbord\n", wantErr: "printable ASCII"},
		{name: "two lines", stdin: "first line\nsecond line\n", wantErr: "more than one line"},
		{name: "empty line, then more", stdin: "\nsomething\n", wantErr: "more than one line"},
		// Value: protects=an unreadable second line (over the scanner's 64 KiB limit) is refused, not taken as end of input; fails_when=the scanner error is ignored and the first line becomes the password; why_new=Codex review; seam=none
		{name: "unreadable second line", stdin: "first line\n" + strings.Repeat("x", 70000) + "\n", wantErr: "reading piped input"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			password, generated, err := promptNewPassword(newPrompter(strings.NewReader(tt.stdin), &out))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if generated {
				t.Errorf("piped input generated a password")
			}
			if password != tt.wantPassword {
				t.Errorf("password = %q, want %q", password, tt.wantPassword)
			}
			if got := strings.Contains(out.String(), "warning"); got != tt.wantWarning {
				t.Errorf("warning shown = %v, want %v; output:\n%s", got, tt.wantWarning, out.String())
			}
			if tt.wantWarning && !strings.Contains(out.String(), "--generate") {
				t.Errorf("the warning on a pipe should point at --generate, not at an empty answer:\n%s", out.String())
			}
		})
	}
}

// Value: protects=a typed password never reaches stdout: the URL then has no password part; fails_when=connURL writes "user:@" or the human output prints the typed password; why_new=connURL gained the no-password form; seam=none
func TestRotatedOutputHidesTypedPassword(t *testing.T) {
	cfg, err := pgx.ParseConfig("postgres://admin@db.example:5432/postgres?sslmode=require")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := connURL(cfg, "shop_app", "", "shop"), "postgres://shop_app@db.example:5432/shop?sslmode=require"; got != want {
		t.Errorf("connURL without password = %s, want %s", got, want)
	}

	// What rotatePassword builds for a typed password: no Password, and a URL
	// made with an empty password.
	var out bytes.Buffer
	printRotated(&out, rotateResult{User: "shop_app", Database: "shop", URL: connURL(cfg, "shop_app", "", "shop")})
	if !strings.Contains(out.String(), "postgres://shop_app@db.example") {
		t.Errorf("output lacks the URL without a password:\n%s", out.String())
	}
	if strings.Contains(out.String(), "password:") || strings.Contains(out.String(), "shown once") {
		t.Errorf("output for a typed password mentions showing it:\n%s", out.String())
	}
}

// Value: protects=flags work on either side of the argument, which the standard flag package doesn't do by itself; fails_when="rotate-password shop_app --json" reads --json as a second user name, or "--" stops being respected; why_new=found by running the binary; seam=none
func TestParseFlagsAfterArgument(t *testing.T) {
	cmd := command{name: "rotate-password", arg: "<user>", json: true}
	tests := []struct {
		args     []string
		wantArg  string
		wantJSON bool
		wantDry  bool
		wantOK   bool
	}{
		{[]string{"shop_app"}, "shop_app", false, false, true},
		{[]string{"--json", "shop_app"}, "shop_app", true, false, true},
		{[]string{"shop_app", "--json"}, "shop_app", true, false, true},
		{[]string{"--dry-run", "shop_app", "--json"}, "shop_app", true, true, true},
		{[]string{"--", "shop_app"}, "shop_app", false, false, true},
		{[]string{"shop_app", "--", "--json"}, "", false, false, false}, // two arguments
		{[]string{"shop_app", "--bogus"}, "", false, false, false},
	}
	for _, tt := range tests {
		var stderr bytes.Buffer
		opts, _, ok := parseFlags(cmd, tt.args, &stderr)
		if ok != tt.wantOK {
			t.Errorf("%q: ok = %v, want %v; stderr: %s", tt.args, ok, tt.wantOK, stderr.String())
			continue
		}
		if ok && (opts.arg != tt.wantArg || opts.json != tt.wantJSON || opts.dryRun != tt.wantDry) {
			t.Errorf("%q: got arg=%q json=%v dry-run=%v, want %q %v %v", tt.args, opts.arg, opts.json, opts.dryRun, tt.wantArg, tt.wantJSON, tt.wantDry)
		}
	}
}

// Value: protects=on a terminal a typed password is asked twice and a mismatch or a refused password asks again instead of failing; fails_when=the confirmation is skipped (a typo in hidden input locks the user out), a mismatch is accepted, or a bad password ends the command like a pipe does; why_new=TestPromptNewPassword only covers piped input, where p.tty is nil; seam=none (sets the existing tty field to a pipe, as TestReadKeys does; fd stays -1, so secret reads lines from in)
func TestPromptNewPasswordOnTerminal(t *testing.T) {
	tests := []struct {
		name          string
		stdin         string
		wantPassword  string // "" means generated
		wantMessage   string // in the prompt output
		wantNoMessage string
		wantErr       string
	}{
		{"confirmed", "correct horse battery\ncorrect horse battery\n", "correct horse battery", "Same password again", "don't match", ""},
		{"mismatch asks again", "correct horse battery\ncorrect horse batery\ncorrect horse battery\ncorrect horse battery\n", "correct horse battery", "don't match", "", ""},
		{"bad password asks again", "smörgåsbord-smörgåsbord\ncorrect horse battery\ncorrect horse battery\n", "correct horse battery", "printable ASCII", "", ""},
		{"generate after a mismatch", "correct horse battery\nsomething else\n\n", "", "don't match", "", ""},
		// Value: protects=input ending at the confirmation is an error, not an unconfirmed password; fails_when=the second secret() error is ignored and the first entry is used; why_new=every row gave a complete second line; seam=none
		{"end of input at confirmation", "correct horse battery\n", "", "", "", "reading password"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()

			var out bytes.Buffer
			p := newPrompter(strings.NewReader(tt.stdin), &out)
			p.tty = r // a terminal as far as promptNewPassword can tell
			password, generated, err := promptNewPassword(p)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v; output:\n%s", err, out.String())
			}
			if generated != (tt.wantPassword == "") {
				t.Errorf("generated = %v, want %v", generated, tt.wantPassword == "")
			}
			if tt.wantPassword != "" && password != tt.wantPassword {
				t.Errorf("password = %q, want %q", password, tt.wantPassword)
			}
			if !strings.Contains(out.String(), tt.wantMessage) {
				t.Errorf("output lacks %q:\n%s", tt.wantMessage, out.String())
			}
			if tt.wantNoMessage != "" && strings.Contains(out.String(), tt.wantNoMessage) {
				t.Errorf("output has %q:\n%s", tt.wantNoMessage, out.String())
			}
		})
	}
}

// Value: protects=piped input is accepted when the admin connection comes from PG* variables alone, as documented; fails_when=the pipe check is narrowed to DATABASE_URL; why_new=only the refusal side was tested; seam=none
func TestRotatePasswordPipeAcceptsPGEnv(t *testing.T) {
	clearConnEnv(t)
	t.Setenv("PGHOST", t.TempDir()) // a socket directory with no server: connecting fails fast
	var stdout, stderr bytes.Buffer
	code := Run([]string{"rotate-password", "shop_app", "--generate"}, strings.NewReader(""), &stdout, &stderr)
	if code == exitUsage || strings.Contains(stderr.String(), "set DATABASE_URL") {
		t.Errorf("piped input refused with PGHOST set: exit %d, stderr:\n%s", code, stderr.String())
	}
}

// Value: protects=the interactive user prompt (terminal, no argument) accepts owners and users alike, re-asks on a bad name, and an argument skips it; fails_when=the prompt validates with ValidateUserName (needs a project), stops validating, or asks despite an argument; why_new=pipe mode refuses a missing argument, so no Run-level test reaches the prompt; seam=none
func TestUserArgOrPrompt(t *testing.T) {
	tests := []struct {
		name, arg, stdin, want, wantErr string
	}{
		{"argument, not asked", "shop_app", "", "shop_app", ""},
		{"owner", "", "shop\n", "shop", ""},
		{"bad name asks again", "", "Shop\npg_x\nshop_app\n", "shop_app", ""},
		{"end of input", "", "", "", "no user name given"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			got, err := userArgOrPrompt(newPrompter(strings.NewReader(tt.stdin), &out), tt.arg)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("got %q, %v; want %q", got, err, tt.want)
			}
			if tt.arg != "" && out.Len() > 0 {
				t.Errorf("asked despite an argument:\n%s", out.String())
			}
		})
	}
}

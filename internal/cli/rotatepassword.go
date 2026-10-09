package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/jschill/nellie/internal/pg"
)

const rotatePasswordHelp = `Gives a user (or a project owner) a new password. Asks for the user if it
isn't given, then for the new password: press Enter to generate one, or type
your own (asked twice). With --generate it doesn't ask. Piped input is read as
one line, so a password can come from a secrets manager:

  op read op://vault/shop-app/password | nellie rotate-password shop_app

With piped input, the input is only the password, on a single, non-empty line,
read until the input ends (close it, or press Ctrl-D if you're typing):
give the user as the argument, and the admin connection in DATABASE_URL (or
.env, or PG* variables). In scripts, use --generate for a generated password.

The old password stops working at once; sessions already connected stay
connected. A generated password is shown once; a typed one is never shown.
`

// shortPassword is the length below which a typed password gets a warning.
const shortPassword = 12

// rotateResult is the --json output. Its fields are a stable interface: the
// names in the `json:"..."` struct tags are what scripts see, and omitempty
// leaves out fields that are empty.
type rotateResult struct {
	User     string `json:"user"`
	Database string `json:"database,omitempty"` // "" if no project database was found
	Password string `json:"password,omitempty"` // only when nellie generated it
	URL      string `json:"url,omitempty"`      // only when Database is known
}

func rotatePassword(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, code, ok := parseFlags(command{name: "rotate-password", help: rotatePasswordHelp, arg: "<user>", json: true, gen: true}, args, stderr)
	if !ok {
		return code
	}
	if opts.arg != "" {
		if err := pg.ValidateRoleName(opts.arg); err != nil {
			fmt.Fprintf(stderr, "nellie: %v\n", err)
			return exitUsage
		}
	}
	if opts.dryRun && opts.json {
		fmt.Fprintln(stderr, "nellie: --json and --dry-run can't be combined: a dry run prints SQL, not a result")
		return exitUsage
	}
	prompt := newPrompter(stdin, stderr)

	// Piped input is the new password and nothing else. Without these checks
	// the user-name or admin-URL prompt would read the password instead, and
	// a dry run would print it as the role name.
	if prompt.tty == nil {
		if opts.arg == "" {
			fmt.Fprintln(stderr, "nellie: with piped input, give the user as an argument: the input is read as the new password")
			return exitUsage
		}
		if !opts.dryRun && os.Getenv("DATABASE_URL") == "" && !hasPGEnv() {
			fmt.Fprintln(stderr, "nellie: with piped input, set DATABASE_URL (in the environment or .env) or the PG* variables for the admin connection: the input is read as the new password")
			return exitUsage
		}
	}

	if opts.dryRun {
		user, err := userArgOrPrompt(prompt, opts.arg)
		if err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "%s%s;\n", dryRunNote, pg.RotateSQL(user, redacted))
		return exitOK
	}

	cfg, err := connConfig(prompt)
	if err != nil {
		return fail(stderr, err)
	}
	user, err := userArgOrPrompt(prompt, opts.arg)
	if err != nil {
		return fail(stderr, err)
	}
	password, generated := pg.NewPassword(), true
	if !opts.gen {
		password, generated, err = promptNewPassword(prompt)
		if err != nil {
			return fail(stderr, err)
		}
	}

	// Nothing to undo here, so plain signal.NotifyContext rather than
	// interruptContext: Ctrl-C just cancels the one statement.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	rot, err := pg.RotatePassword(ctx, cfg, user, password)
	if errors.Is(err, pg.ErrMaybeChanged) {
		// The server may have committed just before the cancel arrived. A
		// Ctrl-C before ALTER ROLE changed nothing and goes through fail.
		fmt.Fprintf(stderr, "nellie: interrupted; the password of %s may or may not have changed, so run this again\n", user)
		return exitInterrupted
	}
	if err != nil {
		return fail(stderr, err)
	}

	// shown is what may be printed: never a password the user typed.
	shown := ""
	if generated {
		shown = password
	}
	res := rotateResult{User: user, Database: rot.Database, Password: shown}
	if rot.Database != "" {
		res.URL = connURL(cfg, user, shown, rot.Database)
	}
	if rot.Expired {
		fmt.Fprintf(stderr, "nellie: warning: the VALID UNTIL of role %s has passed, so it still can't log in; "+
			"clear it with %s\n", user, pg.ClearExpirySQL(user))
	}

	// Build the output first and write it in one go, so a failed write is
	// noticed: the old password is gone, and a generated one exists only here.
	// By default Go kills the process when stdout is a pipe whose reader has
	// gone (SIGPIPE), before Write can return an error; ignoring the signal
	// turns that into an ordinary EPIPE error.
	signal.Ignore(syscall.SIGPIPE)
	var out bytes.Buffer
	if opts.json {
		enc := json.NewEncoder(&out)
		enc.SetIndent("", "  ")
		enc.Encode(res) // can't fail: res holds only strings, and out is in memory
	} else {
		printRotated(&out, res)
	}
	if _, err := stdout.Write(out.Bytes()); err != nil {
		fmt.Fprintf(stderr, "nellie: the password of %s was changed, but the result couldn't be written (%v); run this again for a new one\n", user, err)
		return exitError
	}
	return exitOK
}

// printRotated writes the human output. res.Password is set only for a
// generated password, so a typed one can't be printed here.
func printRotated(w io.Writer, res rotateResult) {
	fmt.Fprintf(w, "Trumpety-trump: %s has a new password.\n\n", res.User)
	switch {
	case res.URL != "":
		fmt.Fprintf(w, "  %s\n\n", res.URL)
	case res.Password != "":
		fmt.Fprintf(w, "  password: %s\n\n", res.Password)
	}
	fmt.Fprintln(w, "The old password has stopped working; sessions already connected stay connected.")
	if res.Password != "" {
		fmt.Fprintln(w, "The password is shown once and stored nowhere else.")
	}
}

// userArgOrPrompt returns the user from the command line, or asks for it.
func userArgOrPrompt(p *prompter, arg string) (string, error) {
	if arg != "" {
		return arg, nil
	}
	return p.ask("User name", "user name", "", pg.ValidateRoleName)
}

// promptNewPassword asks for a password. On a terminal, empty input means
// "generate one", and generated says which happened; a typed password is
// asked twice, since it's hidden and a typo would lock the user out. Piped
// input isn't confirmed, and must be exactly one non-empty line: an empty or
// missing line usually means the command feeding it failed (an unset
// variable in `echo "$PW"`), and only the first of several lines would
// become the password. Scripts that want a generated one use --generate.
func promptNewPassword(p *prompter) (password string, generated bool, err error) {
	for {
		label := "New password (input hidden; empty generates one): "
		if p.tty == nil {
			label = "New password (one line from stdin): "
		}
		typed, err := p.secret(label)
		if errors.Is(err, errNoInput) {
			return "", false, errors.New("no password given; use --generate to have nellie make one")
		}
		if err != nil {
			return "", false, fmt.Errorf("reading password: %w", err)
		}
		if p.tty == nil {
			if p.in.Scan() {
				return "", false, errors.New("more than one line of piped input; the password must be a single line")
			}
			// Scan also stops on errors, such as a line too long to read.
			if err := p.in.Err(); err != nil {
				return "", false, fmt.Errorf("reading piped input: %w", err)
			}
		}
		if typed == "" && p.tty == nil {
			return "", false, errors.New("no password given: the piped line is empty; use --generate to have nellie make one")
		}
		if typed == "" {
			return pg.NewPassword(), true, nil
		}
		if err := pg.ValidatePassword(typed); err != nil {
			if p.tty == nil {
				return "", false, err // a pipe would give the same answer again
			}
			fmt.Fprintln(p.out, err)
			continue
		}

		if p.tty != nil {
			again, err := p.secret("Same password again: ")
			if err != nil {
				return "", false, fmt.Errorf("reading password: %w", err)
			}
			if again != typed {
				fmt.Fprintln(p.out, "The passwords don't match; try again.")
				continue
			}
		}
		if len(typed) < shortPassword {
			hint := "an empty answer generates a long random one"
			if p.tty == nil {
				hint = "--generate makes a long random one"
			}
			fmt.Fprintf(p.out, "nellie: warning: that password is only %d characters long; %s\n", len(typed), hint)
		}
		return typed, false, nil
	}
}

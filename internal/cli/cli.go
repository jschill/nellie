// Package cli implements nellie's subcommands: flag parsing, prompts, output
// and exit codes. All SQL lives in package pg.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Exit codes.
const (
	exitOK    = 0
	exitError = 1 // runtime or database error
	exitUsage = 2 // bad flags or arguments
)

const usage = `nellie: packed her trunk and said goodbye to the circus

Usage: nellie <command> [flags]

Commands:
  add-project   create a database and a role with the same name that owns it
  add-user      add a user that can read and write rows in a project

Run "nellie <command> -h" for a command's flags.
`

// Run dispatches args (without the program name) to a subcommand and returns
// the process exit code. Taking the streams as arguments instead of using
// os.Stdin and friends directly keeps it testable.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	if err := loadDotenv(".env"); err != nil {
		fmt.Fprintf(stderr, "nellie: reading .env: %v\n", err)
		return exitError
	}
	switch args[0] {
	case "add-project":
		return addProject(args[1:], stdin, stdout, stderr)
	case "add-user":
		return addUser(args[1:], stdin, stdout, stderr)
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "nellie: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
}

// connConfig resolves the admin connection, in order: the --dsn flag,
// $DATABASE_URL, the standard PG* environment variables, and finally asking.
// The environment variables may come from a .env file (see loadDotenv).
// Whatever pgx gets, it also reads ~/.pgpass, like psql.
func connConfig(dsn string, p *prompter) (*pgx.ConnConfig, error) {
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn != "" || hasPGEnv() {
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			return nil, fmt.Errorf("parsing connection settings: %w", err)
		}
		return cfg, nil
	}

	for {
		// Hidden, because the URL usually contains the admin password.
		dsn, err := p.secret("Admin connection URL, e.g. postgres://user:pass@localhost:5432/postgres\n" +
			"(input hidden; empty for local defaults; put DATABASE_URL in .env to skip this): ")
		if err != nil {
			return nil, fmt.Errorf("reading connection URL: %w", err)
		}
		cfg, err := pgx.ParseConfig(dsn)
		if err == nil {
			return cfg, nil
		}
		fmt.Fprintln(p.out, err) // pgx redacts the password in its errors
	}
}

// hasPGEnv reports whether any of libpq's connection environment variables is
// set, which means the user has already said where to connect.
func hasPGEnv() bool {
	for _, v := range []string{"PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGSERVICE"} {
		if os.Getenv(v) != "" {
			return true
		}
	}
	return false
}

// options are the flags every command takes.
type options struct {
	dsn    string
	dryRun bool
}

// parseFlags parses a command's flags. If ok is false, the command should
// return code straight away (after -h, or a usage error fs already reported).
func parseFlags(name, help string, args []string, stderr io.Writer) (opts options, code int, ok bool) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.dsn, "dsn", "", "admin connection string (default: $DATABASE_URL, then the PG* environment variables, then ask)")
	fs.BoolVar(&opts.dryRun, "dry-run", false, "print the SQL instead of running it")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: nellie %s [flags]\n\n%s\nFlags:\n", name, help)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return opts, exitOK, false
		}
		return opts, exitUsage, false
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "nellie: %s takes no arguments; it asks for what it needs\n", name)
		return opts, exitUsage, false
	}
	return opts, 0, true
}

// fail reports err and returns the exit code for a runtime error.
func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "nellie: %v\n", err)
	return exitError
}

// connURL builds a connection string for a project role on the same server
// as the admin connection.
func connURL(cfg *pgx.ConnConfig, user, password, db string) string {
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password),
		Path:   "/" + db,
	}
	if strings.HasPrefix(cfg.Host, "/") {
		// A Unix socket directory can't go in the host part of a URL.
		u.RawQuery = url.Values{"host": {cfg.Host}}.Encode()
	} else {
		u.Host = net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port)))
	}
	return u.String()
}

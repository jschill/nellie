// Package cli implements nellie's subcommands: flag parsing, prompts, output
// and exit codes. All SQL lives in package pg.
package cli

import (
	"fmt"
	"io"
	"os"

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
  add-project   create a database with an owner role and an app role

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

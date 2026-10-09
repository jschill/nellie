// Package cli implements nellie's subcommands: flag parsing, prompts, output
// and exit codes. All SQL lives in package pg.
package cli

import (
	"context"
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
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/jschill/nellie/internal/pg"
)

// Exit codes.
const (
	exitOK    = 0
	exitError = 1 // runtime or database error
	exitUsage = 2 // bad flags or arguments
)

// Version is set by main from the VERSION file.
var Version = "unknown"

const usage = `nellie: packed her trunk and said goodbye to the circus

Usage: nellie <command> [flags]

Commands:
  add-project   create a database and a role with the same name that owns it
  add-user      add a user to a project: application (reads and writes) or admin

Run "nellie <command> -h" for a command's flags.
Run "nellie --version" for the version.
`

// Run dispatches args (without the program name) to a subcommand and returns
// the process exit code. Taking the streams as arguments instead of using
// os.Stdin and friends directly keeps it testable.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	// Before .env is read, so a broken .env can't block it.
	switch args[0] {
	case "version", "-version", "--version":
		fmt.Fprintf(stdout, "nellie %s\n", Version)
		return exitOK
	}
	if err := loadDotenv(".env", stderr); err != nil {
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

// connConfig resolves the admin connection: $DATABASE_URL, then the standard
// PG* environment variables, then asking. Whatever pgx gets, it also reads
// ~/.pgpass, like psql.
//
// There is deliberately no --dsn flag: a connection string on the command line
// would carry the admin password into shell history and the process list.
func connConfig(p *prompter) (*pgx.ConnConfig, error) {
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" || hasPGEnv() {
		return parseAdmin(dsn)
	}

	for {
		// Hidden, because the URL usually contains the admin password.
		dsn, err := p.secret("Admin connection URL, e.g. postgres://user:pass@localhost:5432/postgres\n" +
			"(input hidden; empty for local defaults; put DATABASE_URL in .env to skip this): ")
		if err != nil {
			return nil, fmt.Errorf("reading connection URL: %w", err)
		}
		cfg, err := parseAdmin(dsn)
		if err == nil {
			return cfg, nil
		}
		fmt.Fprintln(p.out, err)
	}
}

// errBadURL is what the user sees when pgx can't read the connection settings.
// pgx's own message can echo the connection string, password included, so it
// is never shown.
var errBadURL = errors.New("those connection settings aren't valid; check the URL and try again")

// parseAdmin reads the connection settings with pgx, which handles every form
// it accepts (URL or keyword, service files, PG* variables), then enforces TLS
// on what pgx resolved. Unix sockets don't use TLS and are left alone.
//
// pgx's default, prefer, tries TLS and then plaintext. Here the plaintext
// attempts are dropped, so a server without TLS is an error, not a downgrade.
// That also makes require the effective default, and prefer and an empty
// sslmode behave the same way. sslmode=disable is kept, since it was asked for.
func parseAdmin(dsn string) (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, errBadURL
	}
	if allUnixSockets(cfg) {
		return cfg, nil
	}
	if cfg.TLSConfig == nil {
		for _, fb := range cfg.Fallbacks {
			if fb.TLSConfig != nil {
				return nil, errors.New("sslmode=allow would try plaintext first; use require, verify-full or disable")
			}
		}
		return cfg, nil // sslmode=disable
	}
	var tlsOnly []*pgconn.FallbackConfig
	for _, fb := range cfg.Fallbacks {
		if fb.TLSConfig != nil {
			tlsOnly = append(tlsOnly, fb)
		}
	}
	cfg.Fallbacks = tlsOnly
	return cfg, nil
}

// allUnixSockets reports whether every host pgx will try is a Unix socket.
func allUnixSockets(cfg *pgx.ConnConfig) bool {
	if !strings.HasPrefix(cfg.Host, "/") {
		return false
	}
	for _, fb := range cfg.Fallbacks {
		if !strings.HasPrefix(fb.Host, "/") {
			return false
		}
	}
	return true
}

// sslModeOf names the sslmode a parsed TCP config uses, in libpq's terms, so
// the printed app URLs can repeat it. It reads what pgx resolved, not the
// string, so service files and duplicate keys come out right.
func sslModeOf(cfg *pgx.ConnConfig) string {
	switch {
	case cfg.TLSConfig == nil:
		return "disable"
	case cfg.TLSConfig.VerifyPeerCertificate != nil:
		return "verify-ca" // checked before InsecureSkipVerify, which verify-ca also sets
	case cfg.TLSConfig.InsecureSkipVerify:
		return "require"
	default:
		return "verify-full"
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
	dryRun bool
}

// parseFlags parses a command's flags. If ok is false, the command should
// return code straight away (after -h, or a usage error fs already reported).
func parseFlags(name, help string, args []string, stderr io.Writer) (opts options, code int, ok bool) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
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
	return opts, exitOK, true
}

// fail reports err and returns the exit code for a runtime error. An
// interrupt gets the same code whichever prompt it came from. If the cleanup
// after an interrupt failed too, the message says what was left behind: that
// is more important than saying "interrupted".
func fail(stderr io.Writer, err error) int {
	if errors.Is(err, errInterrupted) || errors.Is(err, context.Canceled) {
		if errors.Is(err, pg.ErrCleanupFailed) {
			fmt.Fprintf(stderr, "nellie: interrupted: %v\n", err)
		} else {
			fmt.Fprintln(stderr, "nellie: interrupted")
		}
		return exitInterrupted
	}
	fmt.Fprintf(stderr, "nellie: %v\n", err)
	return exitError
}

// connURL builds a connection string for a project role on the same server
// as the admin connection. It repeats the admin's sslmode, so the app never
// connects with weaker TLS. Unix sockets have no sslmode.
func connURL(cfg *pgx.ConnConfig, user, password, db string) string {
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password),
		Path:   "/" + db,
	}
	query := url.Values{}
	if allUnixSockets(cfg) {
		// pgx reads a socket directory from the host parameter, so it goes in
		// the query. The port has to travel with it, or it's silently lost.
		query.Set("host", cfg.Host)
		query.Set("port", strconv.Itoa(int(cfg.Port)))
	} else {
		u.Host = net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port)))
		query.Set("sslmode", sslModeOf(cfg))
	}
	u.RawQuery = query.Encode()
	return u.String()
}

// Package cli implements nellie's subcommands: flag parsing, prompts, output
// and exit codes. All SQL lives in package pg.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

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
  add-project       create a database and a role with the same name that owns it
  add-user          add a user to a project: application (reads and writes) or admin
  rotate-password   give a user a new password
  list              list projects and their users (also: trumpet)

Run "nellie <command> -h" for a command's flags.
Run "nellie --version" for the version.
`

// dryRunNote heads every --dry-run script that sets a password (list prints
// its own header, having none). The password is redacted, so piping
// the script to psql would create a role whose password is the text "<redacted>".
const dryRunNote = "-- dry run: the password is redacted, so this script is not meant to be run as is\n"

// interruptContext returns a context that Ctrl-C cancels, and a stop function
// to defer. The first Ctrl-C says what is being undone and gives the
// signal back, so a second Ctrl-C stops the process (leaving what is named
// there behind) instead of being swallowed while cleanup runs.
func interruptContext(stderr io.Writer, name string) (context.Context, func()) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		stop()
		select {
		case <-done: // the command finished; stop() below cancelled ctx, not Ctrl-C
		default:
			fmt.Fprintf(stderr, "\nnellie: interrupted; undoing anything created for %s. Press Ctrl-C again to quit and leave it behind.\n", name)
		}
	}()
	return ctx, func() {
		close(done)
		stop()
	}
}

// Run dispatches args (without the program name) to a subcommand and returns
// the process exit code. Taking the streams as arguments instead of using
// os.Stdin and friends directly keeps it testable.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	// Before .env is read, so a broken .env can't block them.
	switch args[0] {
	case "version", "-version", "--version":
		fmt.Fprintf(stdout, "nellie %s\n", Version)
		return exitOK
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
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
	case "rotate-password":
		return rotatePassword(args[1:], stdin, stdout, stderr)
	case "list", "trumpet":
		return list(args[1:], stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "nellie: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
}

// connConfig resolves the admin connection: $DATABASE_URL, then the standard
// PG* environment variables, then asking. pgx also reads ~/.pgpass, like
// psql, except for a DATABASE_URL from .env (see dotenvConfig).
//
// There is deliberately no --dsn flag: a connection string on the command line
// would carry the admin password into shell history and the process list.
func connConfig(p *prompter) (*pgx.ConnConfig, error) {
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" || hasPGEnv() {
		if dsn == "" || !fromDotenv["DATABASE_URL"] {
			return parseAdmin(dsn)
		}
		return dotenvConfig(p, dsn)
	}

	for {
		// Hidden, because the URL usually contains the admin password.
		dsn, err := p.secret("Admin connection URL, e.g. postgres://user:pass@localhost:5432/postgres\n" +
			"(input hidden; empty for local defaults; put DATABASE_URL in .env to skip this): ")
		if err != nil {
			return nil, fmt.Errorf("reading connection URL: %w", err)
		}
		cfg, err := parseAdmin(strings.TrimSpace(dsn))
		if err == nil {
			return cfg, nil
		}
		fmt.Fprintln(p.out, err)
	}
}

// dotenvConfig resolves a DATABASE_URL from .env, which a checked-out repo
// may have chosen. pgx would mix in every PG* variable from the shell (a
// client certificate, sslmode, a password), so the two never combine; the URL
// must carry its own password and name one host, and nellie says which.
func dotenvConfig(p *prompter, dsn string) (*pgx.ConnConfig, error) {
	if names := pgEnvNames(); len(names) > 0 {
		verb := "is"
		if len(names) > 1 {
			verb = "are"
		}
		return nil, fmt.Errorf("DATABASE_URL comes from .env, but %s %s set in your shell, and pgx would use that "+
			"for whatever server .env names; unset one of them", strings.Join(names, ", "), verb)
	}
	if err := requireOwnPassword(dsn); err != nil {
		return nil, err
	}
	cfg, err := parseAdmin(dsn)
	if err != nil {
		return nil, err
	}
	targets := append([]*pgconn.FallbackConfig{{Host: cfg.Host, Port: cfg.Port, TLSConfig: cfg.TLSConfig}}, cfg.Fallbacks...)
	for _, t := range targets {
		if t.Host != cfg.Host || t.Port != cfg.Port {
			return nil, errors.New("the DATABASE_URL in .env names more than one host; " +
				"nellie only shows one, so give it a single host, or set DATABASE_URL in your shell")
		}
		// pgx loads ~/.postgresql/postgresql.crt and .key by default, and
		// would present them to the server .env names.
		if t.TLSConfig != nil && (len(t.TLSConfig.Certificates) > 0 || t.TLSConfig.GetClientCertificate != nil) {
			return nil, errors.New("a client certificate from ~/.postgresql would be sent to the server the DATABASE_URL " +
				"in .env names; set DATABASE_URL in your shell instead")
		}
	}
	fmt.Fprintf(p.out, "nellie: using DATABASE_URL from .env: %s@%s:%d/%s\n",
		printable(cfg.User), printable(cfg.Host), cfg.Port, printable(cfg.Database))
	return cfg, nil
}

// pgEnvNames returns the PG* variables set in the environment, sorted.
func pgEnvNames() []string {
	var names []string
	for _, kv := range os.Environ() {
		name, value, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "PG") && value != "" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// dotenvURLKeys are the only settings a DATABASE_URL from .env may contain.
// Anything else could make pgx read a file the URL names (passfile, service,
// servicefile, sslkey, ...) and send what it finds to the URL's host.
var dotenvURLKeys = []string{"host", "port", "user", "password", "dbname", "sslmode", "connect_timeout"}

// requireOwnPassword refuses a connection string without a password of its
// own. It's for a DATABASE_URL from .env, which a checked-out repo controls:
// pgx would fill a missing password in from a passfile or a service file and
// send the admin password to whatever host the URL names. The default files
// are hidden while pgx parses, and ConnStringAllowedKeys rejects the URL's
// own (passfile=, service=, ...) before pgx reads any file.
func requireOwnPassword(dsn string) error {
	// No PG* variable is set (see dotenvConfig), but pgx still falls back
	// to ~/.pgpass and ~/.pg_service.conf by default.
	hidden := map[string]string{"PGPASSFILE": os.DevNull, "PGSERVICEFILE": os.DevNull}
	for key, value := range hidden {
		old, had := os.LookupEnv(key)
		os.Setenv(key, value)
		defer func() {
			if had {
				os.Setenv(key, old)
			} else {
				os.Unsetenv(key)
			}
		}()
	}
	cfg, err := pgx.ParseConfigWithOptions(dsn, pgx.ParseConfigOptions{
		ParseConfigOptions: pgconn.ParseConfigOptions{ConnStringAllowedKeys: dotenvURLKeys},
	})
	if err != nil {
		// pgx's message can echo the URL, so it's not shown (see errBadURL).
		return fmt.Errorf("the DATABASE_URL in .env isn't valid, or sets something other than %s; "+
			"set it in your shell instead if it needs more", strings.Join(dotenvURLKeys, ", "))
	}
	if cfg.Password == "" {
		return errors.New("the DATABASE_URL in .env has no password of its own, and nellie won't fill one in from " +
			"~/.pgpass or a service file for a URL a checked-out .env can point anywhere; " +
			"put the password in that URL, or set DATABASE_URL in your shell instead")
	}
	return nil
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

// command describes a subcommand's command line, for parseFlags.
type command struct {
	name string
	help string
	arg  string // the optional argument in the usage line, like "<user>"; "" for none
	json bool   // whether it has --json
	gen  bool   // whether it has --generate
}

// options are the parsed flags, plus the optional argument.
type options struct {
	dryRun bool
	json   bool
	gen    bool
	arg    string // "" if not given
}

// parseFlags parses a command's flags. If ok is false, the command should
// return code straight away (after -h, or a usage error fs already reported).
func parseFlags(cmd command, args []string, stderr io.Writer) (opts options, code int, ok bool) {
	fs := flag.NewFlagSet(cmd.name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&opts.dryRun, "dry-run", false, "print the SQL instead of running it")
	if cmd.json {
		fs.BoolVar(&opts.json, "json", false, "print the result as JSON")
	}
	if cmd.gen {
		fs.BoolVar(&opts.gen, "generate", false, "generate the new password instead of asking for one")
	}
	usageLine := "nellie " + cmd.name + " [flags]"
	if cmd.arg != "" {
		usageLine += " [" + cmd.arg + "]"
	}
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: %s\n\n%s\nFlags:\n", usageLine, cmd.help)
		fs.PrintDefaults()
	}

	// fs.Parse stops at the first argument that isn't a flag, so in
	// "rotate-password shop_app --json" it would leave --json unparsed. Parse
	// again after each argument, until the rest is used up or follows "--".
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return opts, exitOK, false
			}
			return opts, exitUsage, false
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		if parsed := len(args) - len(rest); parsed > 0 && args[parsed-1] == "--" {
			positional = append(positional, rest...)
			break
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}

	switch {
	case len(positional) > 0 && cmd.arg == "":
		fmt.Fprintf(stderr, "nellie: %s takes no arguments; it asks for what it needs\n", cmd.name)
		return opts, exitUsage, false
	case len(positional) > 1:
		fmt.Fprintf(stderr, "nellie: too many arguments\nUsage: %s\n", usageLine)
		return opts, exitUsage, false
	case len(positional) == 1:
		opts.arg = positional[0]
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
			fmt.Fprintf(stderr, "nellie: interrupted: %s\n", terminalSafe(err.Error()))
		} else {
			fmt.Fprintln(stderr, "nellie: interrupted")
		}
		return exitInterrupted
	}
	fmt.Fprintf(stderr, "nellie: %s\n", terminalSafe(err.Error()))
	return exitError
}

// terminalSafe escapes what a terminal would interpret in s: control
// characters other than newline and tab, other non-printing runes, and
// invalid UTF-8. Error text can come from the server, which could otherwise
// send escape sequences to the user's terminal.
func terminalSafe(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[0])
		case r != '\n' && r != '\t' && !unicode.IsPrint(r):
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
		default:
			b.WriteString(s[:size])
		}
		s = s[size:]
	}
	// A server could otherwise start a line that looks like nellie's own.
	return strings.ReplaceAll(b.String(), "\n", "\n  ")
}

// connURL builds a connection string for a project role on the same server
// as the admin connection. It repeats the admin's sslmode, so the app never
// connects with weaker TLS. Unix sockets have no sslmode. An empty password
// leaves it out of the URL.
func connURL(cfg *pgx.ConnConfig, user, password, db string) string {
	u := url.URL{
		Scheme: "postgres",
		User:   url.User(user),
		Path:   "/" + db,
	}
	if password != "" {
		u.User = url.UserPassword(user, password)
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

// writeJSON encodes v as indented JSON into w, with every non-printing
// character escaped as \uXXXX. encoding/json already escapes ASCII control
// characters, but not, say, U+009B (a terminal's CSI) or U+202E (which
// reverses text), and --json output often ends up on a terminal via jq.
func writeJSON(w *bytes.Buffer, v any) {
	var raw bytes.Buffer
	enc := json.NewEncoder(&raw)
	enc.SetIndent("", "  ")
	enc.Encode(v) // can't fail: only strings, bools and slices of them, written to memory
	for s := raw.String(); len(s) > 0; {
		r, size := utf8.DecodeRuneInString(s)
		if r >= utf8.RuneSelf && !unicode.IsPrint(r) {
			// Only inside strings: JSON outside them is plain ASCII.
			if r1, r2 := utf16.EncodeRune(r); r1 != utf8.RuneError {
				fmt.Fprintf(w, `\u%04x\u%04x`, r1, r2)
			} else {
				fmt.Fprintf(w, `\u%04x`, r)
			}
		} else {
			w.WriteString(s[:size])
		}
		s = s[size:]
	}
}

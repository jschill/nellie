// Package cli implements the nellie command line interface.
package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/jschill/nellie/internal/pgadmin"
)

const usage = `nellie - helper for repeating PostgreSQL administration tasks

Usage:
  nellie [--dsn DSN] <command> <subcommand> [flags] [args]

Projects (databases):
  project add <name> [--owner ROLE]        create a project database
  project list                             list project databases
  project remove <name> [--force]          drop a project database

Users (roles):
  user add <name> [-W | --password-stdin] [--createdb] [--nologin]
                                           create a user
  user list                                list users
  user remove <name>                       drop a user
  user passwd <name> [--password-stdin]    change a user's password
  user lock <name>                         disable login for a user
  user unlock <name>                       enable login for a user
  user grant <user> <project> [--readonly] [--schema NAME]
                                           give a user access to a project
  user revoke <user> <project> [--schema NAME]
                                           remove a user's access to a project

Connection:
  The connection string is taken from --dsn, or the NELLIE_DSN environment
  variable. Missing settings fall back to the standard PostgreSQL environment
  variables (PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE, ...).
`

// usageError signals a command line usage error.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// App holds the dependencies of the CLI so they can be replaced in tests.
type App struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	// Connect creates a connector for the given connection string.
	Connect func(dsn string) (pgadmin.Connector, error)
	// ReadPassword interactively reads a password, or returns an error if
	// that is not possible (for example when stdin is not a terminal).
	ReadPassword func(prompt string) (string, error)
}

// Run executes the CLI with args (excluding the program name) and returns the
// process exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	err := a.run(ctx, args)
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		fmt.Fprint(a.Stdout, usage)
		return 0
	case errors.As(err, new(*usageError)):
		fmt.Fprintf(a.Stderr, "nellie: %v\n\n%s", err, usage)
		return 2
	default:
		fmt.Fprintf(a.Stderr, "nellie: %v\n", err)
		return 1
	}
}

func usageErr(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

func (a *App) newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseArgs parses flags in args, allowing flags and positional arguments to
// be mixed, and checks that exactly len(names) positional arguments are given.
func parseArgs(fs *flag.FlagSet, args []string, names ...string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, usageErr("%s: %v", fs.Name(), err)
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		if consumed := len(args) - len(rest); consumed > 0 && args[consumed-1] == "--" {
			pos = append(pos, rest...)
			break
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
	if len(pos) != len(names) {
		want := "no arguments"
		if len(names) > 0 {
			want = "<" + strings.Join(names, "> <") + ">"
		}
		return nil, usageErr("%s: expected %s, got %d argument(s)", fs.Name(), want, len(pos))
	}
	return pos, nil
}

func (a *App) run(ctx context.Context, args []string) error {
	fs := a.newFlagSet("nellie")
	dsn := fs.String("dsn", "", "PostgreSQL connection string")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageErr("%v", err)
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return usageErr("missing command")
	}
	if rest[0] == "help" {
		return flag.ErrHelp
	}
	if len(rest) < 2 {
		return usageErr("missing subcommand for %q", rest[0])
	}
	if *dsn == "" && a.Getenv != nil {
		*dsn = a.Getenv("NELLIE_DSN")
	}

	var cmd func(context.Context, *pgadmin.Admin, []string) error
	switch rest[0] + " " + rest[1] {
	case "project add":
		cmd = a.projectAdd
	case "project list":
		cmd = a.projectList
	case "project remove":
		cmd = a.projectRemove
	case "user add":
		cmd = a.userAdd
	case "user list":
		cmd = a.userList
	case "user remove":
		cmd = a.userRemove
	case "user passwd":
		cmd = a.userPasswd
	case "user lock":
		cmd = a.userLock(false)
	case "user unlock":
		cmd = a.userLock(true)
	case "user grant":
		cmd = a.userGrant
	case "user revoke":
		cmd = a.userRevoke
	default:
		return usageErr("unknown command %q", rest[0]+" "+rest[1])
	}

	// Connecting is deferred until a command needs the database, so argument
	// errors are reported without touching the server.
	admin := pgadmin.New(func(ctx context.Context, database string) (pgadmin.DB, error) {
		connect, err := a.Connect(*dsn)
		if err != nil {
			return nil, err
		}
		return connect(ctx, database)
	})
	return cmd(ctx, admin, rest[2:])
}

func (a *App) projectAdd(ctx context.Context, admin *pgadmin.Admin, args []string) error {
	fs := a.newFlagSet("project add")
	owner := fs.String("owner", "", "existing role that will own the project database")
	pos, err := parseArgs(fs, args, "name")
	if err != nil {
		return err
	}
	if err := admin.CreateProject(ctx, pos[0], *owner); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "Created project %q\n", pos[0])
	return nil
}

func (a *App) projectList(ctx context.Context, admin *pgadmin.Admin, args []string) error {
	if _, err := parseArgs(a.newFlagSet("project list"), args); err != nil {
		return err
	}
	projects, err := admin.ListProjects(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(a.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tOWNER")
	for _, p := range projects {
		fmt.Fprintf(tw, "%s\t%s\n", p.Name, p.Owner)
	}
	return tw.Flush()
}

func (a *App) projectRemove(ctx context.Context, admin *pgadmin.Admin, args []string) error {
	fs := a.newFlagSet("project remove")
	force := fs.Bool("force", false, "terminate existing connections to the database")
	pos, err := parseArgs(fs, args, "name")
	if err != nil {
		return err
	}
	if err := admin.DropProject(ctx, pos[0], *force); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "Removed project %q\n", pos[0])
	return nil
}

// password obtains a password either from stdin or interactively.
func (a *App) password(fromStdin bool) (string, error) {
	if fromStdin {
		line, err := bufio.NewReader(a.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("reading password from stdin: %w", err)
		}
		pw := strings.TrimRight(line, "\r\n")
		if pw == "" {
			return "", errors.New("empty password read from stdin")
		}
		return pw, nil
	}
	if a.ReadPassword == nil {
		return "", errors.New("cannot prompt for password; use --password-stdin")
	}
	pw, err := a.ReadPassword("Enter password: ")
	if err != nil {
		return "", err
	}
	if pw == "" {
		return "", errors.New("password must not be empty")
	}
	again, err := a.ReadPassword("Enter it again: ")
	if err != nil {
		return "", err
	}
	if pw != again {
		return "", errors.New("passwords do not match")
	}
	return pw, nil
}

func (a *App) userAdd(ctx context.Context, admin *pgadmin.Admin, args []string) error {
	fs := a.newFlagSet("user add")
	var prompt bool
	fs.BoolVar(&prompt, "W", false, "prompt for a password")
	fs.BoolVar(&prompt, "password", false, "prompt for a password")
	fromStdin := fs.Bool("password-stdin", false, "read the password from the first line of stdin")
	createDB := fs.Bool("createdb", false, "allow the user to create databases")
	noLogin := fs.Bool("nologin", false, "create the user without login permission")
	pos, err := parseArgs(fs, args, "name")
	if err != nil {
		return err
	}
	if prompt && *fromStdin {
		return usageErr("user add: --password and --password-stdin are mutually exclusive")
	}
	opts := pgadmin.UserOptions{CreateDB: *createDB, NoLogin: *noLogin}
	if prompt || *fromStdin {
		if opts.Password, err = a.password(*fromStdin); err != nil {
			return err
		}
	}
	if err := admin.CreateUser(ctx, pos[0], opts); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "Created user %q\n", pos[0])
	return nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func (a *App) userList(ctx context.Context, admin *pgadmin.Admin, args []string) error {
	if _, err := parseArgs(a.newFlagSet("user list"), args); err != nil {
		return err
	}
	users, err := admin.ListUsers(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(a.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tLOGIN\tSUPERUSER\tCREATEDB\tVALID UNTIL")
	for _, u := range users {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", u.Name, yesNo(u.CanLogin), yesNo(u.Superuser), yesNo(u.CreateDB), u.ValidUntil)
	}
	return tw.Flush()
}

func (a *App) userRemove(ctx context.Context, admin *pgadmin.Admin, args []string) error {
	pos, err := parseArgs(a.newFlagSet("user remove"), args, "name")
	if err != nil {
		return err
	}
	if err := admin.DropUser(ctx, pos[0]); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "Removed user %q\n", pos[0])
	return nil
}

func (a *App) userPasswd(ctx context.Context, admin *pgadmin.Admin, args []string) error {
	fs := a.newFlagSet("user passwd")
	fromStdin := fs.Bool("password-stdin", false, "read the password from the first line of stdin")
	pos, err := parseArgs(fs, args, "name")
	if err != nil {
		return err
	}
	pw, err := a.password(*fromStdin)
	if err != nil {
		return err
	}
	if err := admin.SetPassword(ctx, pos[0], pw); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "Changed password for user %q\n", pos[0])
	return nil
}

func (a *App) userLock(login bool) func(context.Context, *pgadmin.Admin, []string) error {
	name, done := "user lock", "Locked"
	if login {
		name, done = "user unlock", "Unlocked"
	}
	return func(ctx context.Context, admin *pgadmin.Admin, args []string) error {
		pos, err := parseArgs(a.newFlagSet(name), args, "name")
		if err != nil {
			return err
		}
		if err := admin.SetLogin(ctx, pos[0], login); err != nil {
			return err
		}
		fmt.Fprintf(a.Stdout, "%s user %q\n", done, pos[0])
		return nil
	}
}

func (a *App) userGrant(ctx context.Context, admin *pgadmin.Admin, args []string) error {
	fs := a.newFlagSet("user grant")
	readOnly := fs.Bool("readonly", false, "grant read-only access")
	schema := fs.String("schema", "public", "schema to grant access to")
	pos, err := parseArgs(fs, args, "user", "project")
	if err != nil {
		return err
	}
	access, level := pgadmin.ReadWrite, "read-write"
	if *readOnly {
		access, level = pgadmin.ReadOnly, "read-only"
	}
	if err := admin.Grant(ctx, pos[0], pos[1], *schema, access); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "Granted %s access on project %q to user %q\n", level, pos[1], pos[0])
	return nil
}

func (a *App) userRevoke(ctx context.Context, admin *pgadmin.Admin, args []string) error {
	fs := a.newFlagSet("user revoke")
	schema := fs.String("schema", "public", "schema to revoke access to")
	pos, err := parseArgs(fs, args, "user", "project")
	if err != nil {
		return err
	}
	if err := admin.Revoke(ctx, pos[0], pos[1], *schema); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "Revoked access on project %q from user %q\n", pos[1], pos[0])
	return nil
}

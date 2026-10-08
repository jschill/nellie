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
	"os/signal"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/jschill/nellie/internal/pg"
)

const redacted = "<redacted>"

func addProject(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("add-project", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("dsn", "", "admin connection string (default: $DATABASE_URL, then the PG* environment variables, then ask)")
	dryRun := fs.Bool("dry-run", false, "print the SQL instead of running it")
	fs.Usage = func() {
		fmt.Fprint(stderr, `Usage: nellie add-project [flags]

Asks for a project name, then creates a database with that name plus two roles:
<name>_owner owns the database and runs migrations, <name>_app can only read
and write rows.

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage // fs has already printed the error and usage
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(stderr, "nellie: add-project takes no arguments; it asks for the project name")
		return exitUsage
	}

	prompt := newPrompter(stdin, stderr)

	if *dryRun {
		project, err := promptProject(prompt)
		if err != nil {
			fmt.Fprintf(stderr, "nellie: %v\n", err)
			return exitError
		}
		fmt.Fprint(stdout, project.Plan(redacted, redacted).Script(project.Name))
		return exitOK
	}

	// Where to connect first, then what to create. (A dry run needs no connection.)
	cfg, err := connConfig(*dsn, prompt)
	if err != nil {
		fmt.Fprintf(stderr, "nellie: %v\n", err)
		return exitError
	}
	project, err := promptProject(prompt)
	if err != nil {
		fmt.Fprintf(stderr, "nellie: %v\n", err)
		return exitError
	}

	// Set up Ctrl-C handling only after the prompts: while it's active, Ctrl-C
	// no longer kills the process, it cancels ctx.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ownerPassword, appPassword := pg.NewPassword(), pg.NewPassword()
	if err := pg.CreateProject(ctx, cfg, project, ownerPassword, appPassword); err != nil {
		fmt.Fprintf(stderr, "nellie: %v\n", err)
		return exitError
	}

	fmt.Fprintf(stdout, `Nellie packed her trunk: project %s is ready.

  %s  owns the database; run migrations as this role
    %s

  %s  reads and writes rows; use this in the app
    %s

The passwords are shown once and stored nowhere else. Off she went with a trumpety-trump!
`,
		project.Name,
		project.Owner, connURL(cfg, project.Owner, ownerPassword, project.Name),
		project.App, connURL(cfg, project.App, appPassword, project.Name),
	)
	return exitOK
}

// promptProject asks for a project name until it gets a valid one or the
// input ends.
func promptProject(p *prompter) (pg.Project, error) {
	for {
		name, err := p.line("Project name (lowercase letters, digits, _): ")
		if errors.Is(err, errNoInput) {
			return pg.Project{}, errors.New("no project name given")
		}
		if err != nil {
			return pg.Project{}, fmt.Errorf("reading project name: %w", err)
		}
		project, err := pg.NewProject(name)
		if err == nil {
			return project, nil
		}
		fmt.Fprintln(p.out, err)
	}
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

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/jschill/nellie/internal/pg"
)

const addUserHelp = `Asks for a project and a user name, then creates a login role that can read
and write rows in the project's tables, but can't change the schema. That
covers the tables that exist now and the ones the project's owner creates
later, so run migrations as the owner.
`

func addUser(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, code, ok := parseFlags("add-user", addUserHelp, args, stderr)
	if !ok {
		return code
	}
	prompt := newPrompter(stdin, stderr)

	if opts.dryRun {
		user, err := promptUser(prompt)
		if err != nil {
			return fail(stderr, err)
		}
		// Without a connection we can't look up the owner, so assume the
		// add-project convention: a role named like the database.
		fmt.Fprint(stdout, user.Plan(user.Project, redacted).Script(user.Project))
		return exitOK
	}

	cfg, err := connConfig(opts.dsn, prompt)
	if err != nil {
		return fail(stderr, err)
	}
	user, err := promptUser(prompt)
	if err != nil {
		return fail(stderr, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	password := pg.NewPassword()
	if err := pg.AddUser(ctx, cfg, user, password); err != nil {
		return fail(stderr, err)
	}

	fmt.Fprintf(stdout, `Off she went with a trumpety-trump: %s can now read and write in %s.

  %s

The password is shown once and stored nowhere else.
`, user.Name, user.Project, connURL(cfg, user.Name, password, user.Project))
	return exitOK
}

func promptUser(p *prompter) (pg.User, error) {
	project, err := promptProject(p)
	if err != nil {
		return pg.User{}, err
	}
	name, err := p.ask("User name", "user name", project.Name+pg.DefaultUserSuffix, pg.ValidateUserName)
	if err != nil {
		return pg.User{}, err
	}
	return pg.NewUser(name, project.Name)
}

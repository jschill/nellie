package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/jschill/nellie/internal/pg"
)

const redacted = "<redacted>"

const addProjectHelp = `Asks for a project name, then creates a database with that name and a login
role with the same name that owns it and can do everything in it.
Add more users with "nellie add-user".
`

func addProject(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, code, ok := parseFlags("add-project", addProjectHelp, args, stderr)
	if !ok {
		return code
	}
	prompt := newPrompter(stdin, stderr)

	if opts.dryRun {
		project, err := promptProject(prompt)
		if err != nil {
			return fail(stderr, err)
		}
		fmt.Fprint(stdout, project.Plan(redacted).Script(project.Name))
		return exitOK
	}

	// Where to connect first, then what to create. (A dry run needs no connection.)
	cfg, err := connConfig(prompt)
	if err != nil {
		return fail(stderr, err)
	}
	project, err := promptProject(prompt)
	if err != nil {
		return fail(stderr, err)
	}

	// Set up Ctrl-C handling only after the prompts: while it's active, Ctrl-C
	// no longer kills the process, it cancels ctx.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	// Once the first Ctrl-C has cancelled ctx, give the signal back: cleanup can
	// take a while, and a second Ctrl-C should stop it rather than be swallowed.
	go func() {
		<-ctx.Done()
		stop()
	}()

	password := pg.NewPassword()
	if err := pg.CreateProject(ctx, cfg, project, password); err != nil {
		return fail(stderr, err)
	}

	fmt.Fprintf(stdout, `Nellie packed her trunk: project %[1]s is ready.

  %[2]s

%[1]s owns the database and can do everything in it. To add a user that can
only read and write rows, run "nellie add-user".
The password is shown once and stored nowhere else.
`, project.Name, connURL(cfg, project.Name, password, project.Name))
	return exitOK
}

func promptProject(p *prompter) (pg.Project, error) {
	name, err := p.ask("Project name (lowercase letters, digits, _)", "project name", "", pg.ValidateProjectName)
	if err != nil {
		return pg.Project{}, err
	}
	return pg.NewProject(name)
}

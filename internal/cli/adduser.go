package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/jschill/nellie/internal/pg"
)

const addUserHelp = `Asks for a project, a user type and a name, then creates a login role named
<project>_<something> in the project:

  Application  reads and writes rows in the project's tables, but can't change
               the schema. Covers tables that exist now and ones the owner
               creates later, so run migrations as the owner or an admin user.
  Admin        can do everything the owner can, and acts as the owner, so
               tables it creates belong to the owner.
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

	cfg, err := connConfig(prompt)
	if err != nil {
		return fail(stderr, err)
	}
	user, err := promptUser(prompt)
	if err != nil {
		return fail(stderr, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	// Once the first Ctrl-C has cancelled ctx, give the signal back: cleanup can
	// take a while, and a second Ctrl-C should stop it rather than be swallowed.
	go func() {
		<-ctx.Done()
		stop()
	}()

	password := pg.NewPassword()
	if err := pg.AddUser(ctx, cfg, user, password); err != nil {
		return fail(stderr, err)
	}

	what := "can now read and write in"
	if user.Kind == pg.AdminUser {
		what = "can now do everything in"
	}
	fmt.Fprintf(stdout, `Off she went with a trumpety-trump: %s %s %s.

  %s

The password is shown once and stored nowhere else.
`, user.Name, what, user.Project, connURL(cfg, user.Name, password, user.Project))
	return exitOK
}

var userKinds = []struct {
	kind pg.UserKind
	choice
}{
	{pg.AppUser, choice{key: pg.AppUser.DefaultSuffix(), label: "Application", desc: "reads and writes rows, can't change the schema"}},
	{pg.AdminUser, choice{key: pg.AdminUser.DefaultSuffix(), label: "Admin", desc: "can do everything, like the owner"}},
}

func promptUser(p *prompter) (pg.User, error) {
	project, err := promptProject(p)
	if err != nil {
		return pg.User{}, err
	}

	choices := make([]choice, len(userKinds))
	for i, k := range userKinds {
		choices[i] = k.choice
	}
	i, err := p.choose("User type", choices)
	if err != nil {
		return pg.User{}, err
	}
	kind := userKinds[i].kind

	name, err := p.prefixed("User name", project.Name+"_", kind.DefaultSuffix(), pg.MaxNameLen, pg.IsNameChar)
	if err != nil {
		return pg.User{}, err
	}
	return pg.NewUser(kind, name, project.Name)
}

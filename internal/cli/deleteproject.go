package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/jschill/nellie/internal/pg"
)

const deleteProjectHelp = `Permanently deletes a project's database, all its data, and its project roles.
Shows the database and roles first. Type the project name exactly to confirm.
There is no --force flag. Active connections must be closed first.

--dry-run connects to read the actual roles and prints SQL without deleting
anything or asking for confirmation. Connect the admin to another database
(such as postgres), not the project being deleted.
`

func deleteProject(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, code, ok := parseFlags(command{name: "delete-project", help: deleteProjectHelp, arg: "<project>"}, args, stderr)
	if !ok {
		return code
	}
	if opts.arg != "" {
		if err := pg.ValidateProjectName(opts.arg); err != nil {
			fmt.Fprintf(stderr, "nellie: %v\n", err)
			return exitUsage
		}
	}
	prompt := newPrompter(stdin, stderr)
	cfg, err := connConfig(prompt)
	if err != nil {
		return fail(stderr, err)
	}
	name := opts.arg
	if name == "" {
		project, e := promptProject(prompt)
		if e != nil {
			return fail(stderr, e)
		}
		name = project.Name
	}
	// Deletion cannot be undone; don't use the creation command's cleanup message.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	interrupts := make(chan os.Signal, 1)
	defer signal.Stop(interrupts)
	go func() {
		select {
		case <-interrupts:
			cancel()
		case <-ctx.Done():
		}
	}()
	pg.LockWait = func() { fmt.Fprintln(stderr, "nellie: waiting for another nellie run to finish (Ctrl-C to stop)") }
	err = pg.DeleteProject(ctx, cfg, name, opts.dryRun, func(plan pg.Deletion) error {
		if opts.dryRun {
			_, e := fmt.Fprint(stdout, plan.Script())
			return e
		}
		if _, err := fmt.Fprintf(stderr, "Permanently delete database %q and ALL its data.\nRoles to delete:\n", plan.Project); err != nil {
			return fmt.Errorf("writing deletion preview; nothing deleted: %w", err)
		}
		for _, role := range plan.Roles {
			if _, err := fmt.Fprintf(stderr, "  %s\n", printable(role)); err != nil {
				return fmt.Errorf("writing deletion preview; nothing deleted: %w", err)
			}
		}
		answer, e := prompt.rawLine(fmt.Sprintf("Type the project name %q to confirm deletion: ", plan.Project))
		if e != nil {
			return fmt.Errorf("deletion not confirmed; nothing deleted: %w", e)
		}
		if answer != plan.Project {
			return fmt.Errorf("project name did not match; nothing deleted")
		}
		// Leave SIGINT's normal behavior in place while reading stdin. Only
		// intercept it once confirmed, when cancellation must report progress.
		signal.Notify(interrupts, os.Interrupt)
		return nil
	})
	if err != nil {
		// Keep deletion progress: a generic interrupt message would hide
		// that the database is already gone or that its state is uncertain.
		if errors.Is(err, context.Canceled) {
			fmt.Fprintf(stderr, "nellie: interrupted: %s\n", terminalSafe(err.Error()))
			return exitInterrupted
		}
		return fail(stderr, err)
	}
	if opts.dryRun {
		return exitOK
	}
	if _, err = fmt.Fprintf(stdout, "Nellie packed up the circus: project %s and its roles are deleted.\n", name); err != nil {
		return fail(stderr, err)
	}
	return exitOK
}

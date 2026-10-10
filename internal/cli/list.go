package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/jschill/nellie/internal/pg"
)

const listHelp = `Lists the projects the admin role can act for: the databases whose owner it
is, or is a member of. Under each project come its users, the login roles
named <project>_<something> that can connect to it:

  application  reads and writes rows
  admin        has the owner's privileges, so it can do everything

It only reads, and shows no passwords. Also known as "nellie trumpet".
`

// listProject and listUser are the --json output. Like rotateResult, the
// field names in the tags are a stable interface.
type listProject struct {
	Project string     `json:"project"`
	Owner   string     `json:"owner"`
	Users   []listUser `json:"users"`
}

type listUser struct {
	Name    string `json:"name"`
	Type    string `json:"type"`    // "application" or "admin"
	Expired bool   `json:"expired"` // VALID UNTIL has passed
}

func list(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, code, ok := parseFlags(command{name: "list", help: listHelp, json: true}, args, stderr)
	if !ok {
		return code
	}
	if opts.dryRun && opts.json {
		fmt.Fprintln(stderr, "nellie: --json and --dry-run can't be combined: a dry run prints SQL, not a result")
		return exitUsage
	}
	if opts.dryRun {
		fmt.Fprintf(stdout, "-- dry run: nellie list runs this one query, which only reads\n%s;\n", pg.ListSQL)
		return exitOK
	}

	cfg, err := connConfig(newPrompter(stdin, stderr))
	if err != nil {
		return fail(stderr, err)
	}
	// Nothing to undo: Ctrl-C just cancels the query.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	projects, err := pg.ListProjects(ctx, cfg)
	if err != nil {
		return fail(stderr, err)
	}

	var out bytes.Buffer
	if opts.json {
		enc := json.NewEncoder(&out)
		enc.SetIndent("", "  ")
		enc.Encode(listJSON(projects)) // can't fail: only strings and bools, written to memory
	} else {
		printList(&out, projects)
	}
	if _, err := stdout.Write(out.Bytes()); err != nil {
		fmt.Fprintf(stderr, "nellie: writing the list: %v\n", err)
		return exitError
	}
	return exitOK
}

// listJSON converts projects to the --json shape. The slices are made
// non-nil, because encoding/json writes a nil slice as null and an empty one
// as [], and scripts shouldn't have to handle both.
func listJSON(projects []pg.ProjectInfo) []listProject {
	res := make([]listProject, 0, len(projects))
	for _, p := range projects {
		lp := listProject{Project: p.Name, Owner: p.Owner, Users: make([]listUser, 0, len(p.Users))}
		for _, u := range p.Users {
			lp.Users = append(lp.Users, listUser{Name: u.Name, Type: u.Kind.String(), Expired: u.Expired})
		}
		res = append(res, lp)
	}
	return res
}

// printList writes the human output: each project with its owner, then its
// users in aligned columns.
func printList(w io.Writer, projects []pg.ProjectInfo) {
	if len(projects) == 0 {
		fmt.Fprintln(w, `The big top is empty: the admin role can't act for any project yet. Make one with "nellie add-project".`)
		return
	}
	// A tabwriter pads tab-separated cells so columns line up. Lines without
	// a tab (the project lines) end a block, so each project aligns on its own.
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for i, p := range projects {
		if i > 0 {
			fmt.Fprintln(tw)
		}
		fmt.Fprintf(tw, "%s  (owner %s)\n", printable(p.Name), printable(p.Owner))
		if len(p.Users) == 0 {
			fmt.Fprintln(tw, `  no users yet; add one with "nellie add-user"`)
		}
		for _, u := range p.Users {
			// u.Kind prints as "admin" or "application" through its String method.
			fmt.Fprintf(tw, "  %s\t%s", printable(u.Name), u.Kind)
			if u.Expired {
				fmt.Fprint(tw, "\tVALID UNTIL has passed, so it can't log in")
			}
			fmt.Fprintln(tw)
		}
	}
	tw.Flush()
}

// printable returns name as is, or quoted with escapes if it holds characters
// that aren't printable. nellie's own names are always plain, but list also
// shows databases and roles it didn't create, and a name with control
// characters could otherwise send escape sequences to the terminal.
func printable(name string) string {
	if strings.ContainsFunc(name, func(r rune) bool { return !unicode.IsPrint(r) }) {
		return strconv.Quote(name)
	}
	return name
}

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
	"unicode/utf8"

	"github.com/jschill/nellie/internal/pg"
)

const listHelp = `Lists the projects the admin role can act for: the databases it owns, or
whose owner's privileges it has through membership. Under each project come
its users, the login roles named <project>_<something> (or exactly <project>,
when that role isn't the owner); a role goes under the longest database its
name matches, and a note says when it can't connect:

  application  any other user, such as one made by "nellie add-user"
               as an application user, which reads and writes rows
  admin        a member of the owner role, so it has (or can take) the
               owner's privileges and can do everything
  privileged   has powers beyond the project, shown next to it: SUPERUSER,
               CREATEROLE, CREATEDB, REPLICATION, BYPASSRLS, membership in
               a role that has them or in a predefined pg_* role, or owning
               another database (directly or through membership). An owner
               with such powers is marked on the project line.

The admin role itself isn't listed as a user. It only reads, and shows no
passwords. Also known as "nellie trumpet".
`

// listProject and listUser are the --json output. Like rotateResult, the
// field names in the tags are a stable interface.
type listProject struct {
	Project     string     `json:"project"`
	Owner       string     `json:"owner"`
	OwnerPowers []string   `json:"owner_powers"` // the owner's powers beyond the project, [] for none
	Users       []listUser `json:"users"`
}

type listUser struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`        // "application", "admin" or "privileged"
	Powers     []string `json:"powers"`      // why it's privileged, one per element; [] if it isn't
	CanConnect bool     `json:"can_connect"` // may connect to the project's database
	Expired    bool     `json:"expired"`     // VALID UNTIL has passed: the password no longer works
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
		fmt.Fprint(stdout, "-- dry run: what nellie list runs (between the two statements it also checks the session's role and the server version); it only reads\n"+pg.ListScript())
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
		lp := listProject{Project: p.Name, Owner: p.Owner, OwnerPowers: nonNil(p.OwnerPowers), Users: make([]listUser, 0, len(p.Users))}
		for _, u := range p.Users {
			lp.Users = append(lp.Users, listUser{Name: u.Name, Type: userType(u), Powers: nonNil(u.Powers), CanConnect: u.CanConnect, Expired: u.Expired})
		}
		res = append(res, lp)
	}
	return res
}

// nonNil returns s, or an empty slice for nil, so --json writes [] (see listJSON).
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// powersNote joins powers for the human output, each escaped on its own.
func powersNote(powers []string) string {
	shown := make([]string, len(powers))
	for i, p := range powers {
		shown[i] = printable(p)
	}
	return strings.Join(shown, ", ")
}

// userType names a user's type for both outputs: "privileged" when it has
// powers beyond the project, whatever its membership, else its kind.
func userType(u pg.UserInfo) string {
	if len(u.Powers) > 0 {
		return "privileged"
	}
	return u.Kind.String()
}

// printList writes the human output: each project with its owner, then its
// users in aligned columns (name, type, notes).
func printList(w io.Writer, projects []pg.ProjectInfo) {
	if len(projects) == 0 {
		fmt.Fprintln(w, `The big top is empty: the admin role can't act for any project yet. Make one with "nellie add-project".`)
		return
	}
	// A tabwriter pads tab-separated cells so columns line up. Lines without
	// a tab (the project lines) end a block, so each project aligns on its own.
	// Every user line has all three cells, even with no notes, so the notes
	// line up too; the padding that leaves at line ends is trimmed below.
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	for i, p := range projects {
		if i > 0 {
			fmt.Fprintln(tw)
		}
		owner := printable(p.Owner)
		if len(p.OwnerPowers) > 0 {
			owner += ", privileged: " + powersNote(p.OwnerPowers)
		}
		fmt.Fprintf(tw, "%s  (owner %s)\n", printable(p.Name), owner)
		if len(p.Users) == 0 {
			fmt.Fprintln(tw, `  no users yet; add one with "nellie add-user"`)
		}
		for _, u := range p.Users {
			fmt.Fprintf(tw, "  %s\t%s", printable(u.Name), userType(u))
			var notes []string
			if len(u.Powers) > 0 {
				notes = append(notes, powersNote(u.Powers))
			}
			if !u.CanConnect {
				notes = append(notes, "can't connect")
			}
			if u.Expired {
				notes = append(notes, "password expired (VALID UNTIL)")
			}
			fmt.Fprintln(tw, "\t"+strings.Join(notes, "; "))
		}
	}
	tw.Flush()
	for line := range strings.Lines(buf.String()) {
		fmt.Fprintln(w, strings.TrimRight(line, " \n"))
	}
}

// printable returns name as is, or quoted with escapes if it holds characters
// that aren't printable. nellie's own names are always plain, but list also
// shows databases and roles it didn't create, and a name with control
// characters could otherwise send escape sequences to the terminal. Bytes that
// aren't valid UTF-8 count too: ContainsFunc would read them as U+FFFD, which
// is printable, and pass on a raw byte such as 0x9b (CSI on some terminals).
func printable(name string) string {
	if !utf8.ValidString(name) || strings.ContainsFunc(name, func(r rune) bool { return !unicode.IsPrint(r) }) {
		return strconv.Quote(name)
	}
	return name
}

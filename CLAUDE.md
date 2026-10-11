# nellie

A Go CLI for basic Postgres provisioning: creating projects, users/roles, and
managing their passwords.

## Tone

Named after "Nellie the Elephant" (the Toy Dolls' punk cover): Postgres's mascot
is an elephant, and Nellie packs up users and projects and sends them off to the DB.

- Silly but competent. Puns are welcome in help text and human-facing success
  messages only — never in error messages, flag names, `--json` output, or
  anything a script might parse.
- Tagline / help-text subtitle: "packed her trunk and said goodbye to the circus".
- Success message on user creation can riff on "off she went with a trumpety-trump".

## Learning project

nellie is written in Go partly because the author is learning Go — it's a
deliberately reasonable-sized first project. That shapes how to work here:

- Explain Go idioms briefly the first time they show up (error wrapping with
  `%w`, `defer`, `context.Context`, interfaces, zero values, …). One or two
  sentences, not a tutorial.
- Write idiomatic, boring Go over clever Go: explicit error handling, small
  interfaces defined where they're used, `ctx` as the first parameter,
  table-driven tests.
- Prefer the standard library. Add a dependency only when it clearly earns its
  place, and say why.
- Work in small, reviewable steps rather than scaffolding everything at once.
- When the author has written code, review and explain rather than rewrite,
  unless asked to rewrite.

## Stack

- Go 1.27, module `github.com/jschill/nellie`.
- CLI: standard library `flag`, one `flag.FlagSet` per subcommand, dispatched
  from `os.Args[1]`. No CLI framework — the command set is small and building
  the dispatch by hand is part of the learning.
- Postgres driver: `github.com/jackc/pgx/v5`. No ORM.
- Layout:
  - `main.go` — embeds `VERSION` (`go:embed`), sets `cli.Version`, calls `cli.Run`.
- `VERSION` — the release version, `MAJOR.MINOR.PATCH.MICRO` (gstack-ship bumps it). `nellie --version` prints it.
  - `internal/cli/` — dispatch plus one file per subcommand: flags, prompts,
    output, exit codes. (Not `cmd/`: in Go, `cmd/<name>/` holds `main`
    packages.)
  - `internal/pg/` — all SQL and database logic. The cli package never builds SQL.

## Commands

Short, lowercase, verb-noun subcommands:

```
nellie add-project     # asks for the name (done)
nellie add-user        # asks for project and user name (done)
nellie rotate-password [<user>]   # asks for the user if not given (done)
nellie list            # alias: nellie trumpet (done)
```

`rotate-password` asks for the new password; empty input on a terminal, or
`--generate`, generates one.
Typed passwords are hidden and asked twice on a terminal; piped input is read
as one non-empty line, unconfirmed (that's the secrets-manager path, so
there's no `--password-stdin`); an empty piped line is an error, not
"generate". With piped input the input is only the password: the
user must be the argument and the admin connection must come from the
environment, else exit 2. It refuses roles that `list` doesn't show (no
project by `shownProject`; on Postgres 15 CREATEROLE could rotate anyone),
roles that don't exist, can't log in,
are superusers, are the admin itself, have `CREATEROLE`, `REPLICATION` or
`BYPASSRLS`, or are members of a role that has, or of any predefined `pg_*`
role except `pg_database_owner` (`list` shows those as `privileged`); it warns when the role's `VALID UNTIL` has passed. Piped input must
be a single line. The URL's database is the longest prefix
of the role name (cut at `_`, or the whole name) that is an existing
database, by name alone like `list` (`projectHome`); there's a URL only if
that database is one of the admin's projects, owned by the role named after
it, and the role can connect to it (`canConnectExpr`, shared with `list`).
Never a shorter one: picking by CONNECT let database owners redirect the URL,
and the owner rule stops a CREATEDB role's look-alike database. It warns,
like `list`, about powers beyond the project and template projects, both
computed against the project `list` shows the role under (`shownProject`;
the project predicate is `isProjectExpr`, shared with `list`).

`list` shows the databases whose owner's privileges the admin has
(`pg_has_role(datdba, 'USAGE')`, as in `add-user`; not `'MEMBER'`, which on
Postgres 16+ also matches the ADMIN-only membership a `CREATEROLE` admin keeps
in every role it created). Templates and databases closed to connections stay
in, since the owner controls both settings; `template0`/`template1` are left
out by name. Users are the `LOGIN` roles named `<db>_*` (or exactly `<db>`),
assigned by name alone to the longest matching database among all of them.
Never assign by CONNECT or membership: some database owner controls those,
and every such rule let an owner hide or move roles (three review passes, see
JSC-3). A role that can't connect (`datallowconn`, connection limits of 0
on the database or role unless superuser, and CONNECT) gets a
`can_connect: false` note. A role whose home database (by name) isn't a
project, being invisible or invalid, is shown under the longest project its
name matches with `belongs_to` naming the home, so it can't vanish. The owner (by OID) and the admin
itself are never users. Types: `admin` is `'MEMBER'` of the owner, on purpose
(a NOINHERIT member can still `SET ROLE` to it); `privileged` has what
`rotate-password` refuses, `CREATEDB` (it could create a database that
matches a user's name), or owns another database (directly or through
membership; compare database OIDs, not owner OIDs), listed in `powers`, one
power per array element so a name containing ", " can't fake one; the rest
are `application`. The owner's powers are computed the same way
(`owner_powers`); projects also carry `template` and `foreign_owner` (owner
not named after the database), both noted on the project line. Powers come
from one shared SQL fragment (`powersExpr`, also used by
`rotate-password`); superusers and `CREATEROLE` roles skip the memberships,
which would list every role they manage. On Postgres 15 an owner can revoke the admin's membership
and so drop out of `list`; that's documented, not handled. It runs `pg.ListSQL` (one query, no
bind parameters) after `pinSession` and the version check; `--dry-run` prints
the pin and the query (`pg.ListScript`).

`pinSession` (sql.go) starts the admin connection of every command: it pins
`search_path`, refuses a `NOINHERIT` admin (which can't use the owners'
privileges, so `list` would be empty), and refuses a session acting as
another role unless the admin's own `ALTER ROLE ... SET role` explains it. It
fails closed on purpose: checking the database's `role` setting instead races
with its owner clearing it. That setting only picks the error's advice
(`ALTER DATABASE` vs a role in the connection settings).

Common flags, registered on every subcommand's FlagSet: `--dry-run`, and
`--json` where output is data (e.g. `list`). No `--dsn`: a connection string
on the command line would carry the admin password into shell history and the
process list.

## Build, test, lint

```
go build ./...
go test ./...                      # unit tests, no database needed
go test -tags integration ./...    # needs NELLIE_TEST_DSN, see Testing
go vet ./... && go vet -tags integration ./...
gofmt -l .                         # must print nothing
```

Run all of these before calling a change done.

## Connecting to Postgres

- Connection precedence: `DATABASE_URL` > standard libpq `PG*` env vars
  (`PGHOST`, `PGUSER`, …, honored by `pgx.ParseConfig`) > asking.
- TLS: `parseAdmin` (cli.go) lets pgx parse the settings, then drops the
  plaintext attempts from the resolved config. So `prefer`, an empty sslmode
  and the default all become `require`; `sslmode=disable` is honored when set;
  `sslmode=allow` is refused. Parsing the string by hand is what the red team
  broke (keyword spaces, duplicate keys, service files), so don't reintroduce
  it. `require` encrypts but doesn't verify the server certificate, a
  deliberate trade-off (see README). Unix sockets are exempt. `connURL` repeats
  the admin's resolved sslmode (`sslModeOf`) in the app URLs.
- Errors from pgx can echo the connection string, so `parseAdmin` returns a
  fixed message instead. Keep it that way.
- Asking: the prompt hides input on a terminal (`golang.org/x/term`), since the
  URL usually holds the admin password; empty input means pgx's local defaults.
  `~/.pgpass` works via pgx in every case.
- `cli.Run` loads `.env` from the current directory first (own small parser
  in `internal/cli/dotenv.go`, no dependency). Variables already set in the
  environment win. Only `DATABASE_URL` loads; every other key (`PG*`,
  `SSL_CERT_*`, `GODEBUG`, ...) is skipped with a warning, so a checked-out
  `.env` can't redirect the admin connection or change Go's TLS and DNS
  behavior. A byte order mark is stripped. A `DATABASE_URL` from `.env`
  (`fromDotenv`) is refused next to `PG*` connection settings from the shell
  (`hasPGEnv`), its host is printed to stderr, and it must carry its own
  password, so `requireOwnPassword` hides pgx's PGPASSWORD, passfile and service
  fallbacks while parsing it, and allows only the keys in `dotenvURLKeys`
  (pgx's `ConnStringAllowedKeys`), so the URL can't name a passfile, service
  or key file itself. `.env` is gitignored; `.env.example` shows the format.
- All prompts in a command share one `prompter` (`internal/cli/prompt.go`):
  `bufio.Scanner` reads ahead, so a second scanner on stdin can lose input.
  Prompts go to stderr, so stdout stays clean.
- Interactive widgets (menu, prefixed input) live in `internal/cli/tui.go`:
  raw mode via `x/term`, ANSI escapes, no UI library. Each has a plain line
  fallback when stdin isn't a terminal, which is what the tests exercise.
  One `Read` can hold several keys, so input is always split per byte.
- The admin role needs `CREATEROLE` and `CREATEDB`. Superuser is not required —
  don't add features that silently need it.
- Postgres 15 or newer (checked at runtime): the grants rely on the public
  schema being owned by `pg_database_owner`.

## Data model

Like Supabase: a project starts with **one role that can do everything**, and
more restricted users are added separately.

- `add-project <name>` creates:
  - the database `<name>`, owned by the role `<name>`. All privileges are
    revoked from `PUBLIC` (not just CONNECT, which leaves TEMPORARY open), so
    app users can't create temp tables.
  - the role `<name>` (`LOGIN`): owns the database and its public schema, so
    it can do everything, including running migrations.
- `add-user` asks for a project, a user type (arrow-key menu) and a name,
  and creates a `LOGIN` role in an existing project. User names are always
  `<project>_<suffix>`; only the suffix can be edited (default `app` or
  `admin`). Two types:
  - **Application** (default): `SELECT, INSERT, UPDATE, DELETE` on tables
    and `USAGE, SELECT` on sequences. No DDL, no `TRUNCATE`. Covers tables
    that exist now (`GRANT ... ON ALL TABLES`) and ones the owner creates
    later (`ALTER DEFAULT PRIVILEGES FOR ROLE <owner>`), so migrations
    **must** run as the owner (or an admin user) or new tables are invisible
    to app users.
  - **Admin**: member of the owner role, plus
    `ALTER ROLE <user> IN DATABASE <db> SET role TO "<owner>"`, so its
    sessions act as the owner and whatever it creates is owned by the owner.
    That keeps the default privileges for app users working.
- The owner is looked up in `pg_database`, so `add-user` also works for
  databases nellie didn't create, as long as the admin is a member of their
  owner.
- The admin role grants itself membership in each project owner and keeps it:
  on Postgres 16+ `CREATEROLE` no longer implies it, and
  `CREATE DATABASE ... OWNER`, `GRANT ... ON ALL TABLES` and
  `ALTER DEFAULT PRIVILEGES FOR ROLE` need it.
- Names: `^[a-z][a-z0-9_]*$`, no `pg_` prefix, so they're valid unquoted
  identifiers. Users max 63 chars; projects max 57, so the default
  `<project>_admin` still fits.
- Names map to projects by longest prefix (`list`, `rotate-password`), so
  they must not overlap (`ErrAmbiguous`, JSC-3): `add-project <p>` refuses
  when it would take over a login role (not the admin) named `<p>_…` that no
  longer database already claims, and `add-user` refuses a name that a
  database longer than its project would claim. Databases and `NOLOGIN` roles
  don't block a project name. Errors quote catalog names (`%q`). Residual
  risk, documented: the guard trusts longer databases to stay, but the owner
  of `<p>_x` can drop it later, and its `<p>_x_*` roles then show under `<p>`
  as plain users. Names that overlap
  from before stay possible; `list` and `rotate-password` assign them by name
  and only give a URL for a database owned by the role named after it.

## Safety rules

These are non-negotiable — the tool creates roles and sets passwords.

- **Identifiers:** role and database names can't be bind parameters. Always quote
  with `pgx.Identifier{name}.Sanitize()`. Never `fmt.Sprintf` a raw name into SQL.
  Also validate names up front (see Data model) and reject anything else with
  a clear error.
- **Passwords:**
  - Never accept a password as a flag value or argument (shell history,
    `ps`). Either generate one or prompt for it (hidden on a terminal).
  - Generated passwords: `crypto/rand.Text()` (26 chars, 130 bits), printed
    once to stdout and nowhere else. A password the user typed is never
    printed back, not even in `--json`.
  - Typed passwords must be printable ASCII: Postgres runs passwords through
    SASLprep before hashing, and nellie's client-side verifier doesn't, so
    non-ASCII passwords could hash differently and never work.
  - Compute the SCRAM-SHA-256 verifier client-side and send that in
    `CREATE/ALTER ROLE ... PASSWORD`, so plaintext never reaches server logs
    (same approach as psql's `\password`).
  - Never log, wrap into errors, or echo passwords — including in `--dry-run`
    output (print `<redacted>`).
- **Transactions:** multi-statement operations run in one transaction where
  Postgres allows it. `CREATE DATABASE` can't run in a transaction, so on failure
  after it, clean up explicitly and say what was left behind.
- **Existing objects:** `add-*` fails with a clear error if the role or
  database already exists. No silent no-ops, no `--force`.
- **`--dry-run`** prints the SQL that would run and touches nothing.

## Output and exit codes

- Human output to stdout, errors to stderr. `fail` escapes control
  characters in error text (`terminalSafe`), since some of it comes from the
  server.
- `--json` output is stable and pun-free.
- Exit codes: `0` success, `1` runtime/database error, `2` usage error,
  `130` interrupted by Ctrl-C (128 + SIGINT, from either kind of prompt).

## Testing

- Unit tests cover name validation, SQL generation, and password/verifier code
  without a database.
- Integration tests (`//go:build integration`) run against the real Postgres in
  `NELLIE_TEST_DSN` and skip if it's unset. Don't mock the database for
  anything that touches SQL semantics or privileges. Use a throwaway server and
  a non-superuser admin, which is the setup that catches privilege bugs:

  ```
  docker run --rm -d --name nellie-pg -e POSTGRES_PASSWORD=postgres -p 55439:5432 postgres:18
  docker exec nellie-pg psql -U postgres -c "CREATE ROLE nellie_admin LOGIN CREATEROLE CREATEDB PASSWORD 'admin'"
  NELLIE_TEST_DSN=postgres://nellie_admin:admin@localhost:55439/postgres go test -tags integration ./...
  ```

## Open items

- Check that `nellie` isn't taken in Homebrew core before publishing (the Go
  module path can't collide; a personal tap sidesteps Homebrew entirely).
- Clarify the relationship with `pg2k` (shared code? conventions to copy?). It
  isn't checked out next to this repo.

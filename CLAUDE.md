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
  - `main.go` — calls `cli.Run`, nothing else.
  - `internal/cli/` — dispatch plus one file per subcommand: flags, prompts,
    output, exit codes. (Not `cmd/`: in Go, `cmd/<name>/` holds `main`
    packages.)
  - `internal/pg/` — all SQL and database logic. The cli package never builds SQL.

## Commands

Short, lowercase, verb-noun subcommands:

```
nellie add-project     # asks for the name (done)
nellie add-user <user> --project <name>
nellie rotate-password <user>
nellie list            # alias: nellie trumpet
```

Common flags, registered on every subcommand's FlagSet: `--dsn`, `--dry-run`,
`--json` (where output is data, e.g. `list`).

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

- Connection precedence: `--dsn` flag > `DATABASE_URL` > standard libpq `PG*`
  env vars (`PGHOST`, `PGUSER`, …, honored by `pgx.ParseConfig`) > asking.
  The prompt hides input on a terminal (`golang.org/x/term`), since the URL
  usually holds the admin password; empty input means pgx's local defaults.
  `~/.pgpass` works via pgx in every case.
- `cli.Run` loads `.env` from the current directory first (own small parser
  in `internal/cli/dotenv.go`, no dependency). Variables already set in the
  environment win. `.env` is gitignored; `.env.example` shows the format.
- All prompts in a command share one `prompter` (`internal/cli/prompt.go`):
  `bufio.Scanner` reads ahead, so a second scanner on stdin can lose input.
  Prompts go to stderr, so stdout stays clean.
- The admin role needs `CREATEROLE` and `CREATEDB`. Superuser is not required —
  don't add features that silently need it.
- Postgres 15 or newer (checked at runtime): the grants rely on the public
  schema being owned by `pg_database_owner`.

## Data model

A **project is a database with two roles**, all derived from one name:

- `<name>` — the database, owned by `<name>_owner`. `CONNECT` is revoked from
  `PUBLIC` and granted only to the two roles.
- `<name>_owner` — `LOGIN`; owns the database and the public schema, runs
  migrations. Default privileges give `_app` access to everything it creates,
  so migrations **must** run as this role or `_app` gets no access.
- `<name>_app` — `LOGIN`; `SELECT, INSERT, UPDATE, DELETE` on tables and
  `USAGE, SELECT` on sequences. No DDL, no `TRUNCATE`.
- The admin role grants itself membership in `<name>_owner`: on Postgres 16+
  `CREATEROLE` no longer implies it, and `CREATE DATABASE ... OWNER` and
  `ALTER DEFAULT PRIVILEGES FOR ROLE` need it.
- Project names: `^[a-z][a-z0-9_]*$`, max 57 chars (63 minus `_owner`), no
  `pg_` prefix. That keeps the database and both role names valid unquoted
  identifiers.

## Safety rules

These are non-negotiable — the tool creates roles and sets passwords.

- **Identifiers:** role and database names can't be bind parameters. Always quote
  with `pgx.Identifier{name}.Sanitize()`. Never `fmt.Sprintf` a raw name into SQL.
  Also validate names up front (see Data model) and reject anything else with
  a clear error.
- **Passwords:**
  - Never accept a password as a flag value or argument (shell history,
    `ps`). Either generate one or read it with `--password-stdin`.
  - Generated passwords: `crypto/rand.Text()` (26 chars, 130 bits), printed
    once to stdout and nowhere else.
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

- Human output to stdout, errors to stderr.
- `--json` output is stable and pun-free.
- Exit codes: `0` success, `1` runtime/database error, `2` usage error.

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

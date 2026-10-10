# nellie 🐘

A small Go CLI for the Postgres chores you do over and over: setting up a
database for a new project, and adding the users that go with it.

Postgres's mascot is an elephant. So is Nellie. She takes a project name,
packs up a database, a role and a fresh password, and sends them off to your
server, with none of the `GRANT` gymnastics left for you to remember.

```
$ nellie add-project
Project name (lowercase letters, digits, _): shop
Nellie packed her trunk: project shop is ready.

  postgres://shop:4JZQ…@localhost:5432/shop
```

## What you get

nellie works the way Supabase does: a project starts with **one role that can
do everything**, and you add more restricted users when you need them.

| Command | Creates |
| --- | --- |
| `nellie add-project` | A database `shop` and a login role `shop` that owns it. Other roles can't connect. |
| `nellie add-user` → Application | `shop_app`, which can read and write rows but can't touch the schema. For your app. |
| `nellie add-user` → Admin | `shop_admin`, which can do everything the owner can. For people and migrations. |

`add-project` and `add-user` ask for everything interactively, so there are no
flags to look up; `rotate-password` asks for whatever you don't give it.
`nellie list` (or `nellie trumpet`) shows what you've got.
Names are checked as you type, and a bad one never gets anywhere near the
server.

## Install

You need Go 1.27 or newer.

```bash
go install github.com/jschill/nellie@latest
```

Or from a checkout:

```bash
go build -o nellie .
```

Check what you got with `nellie --version`.

## The admin role

nellie connects as an admin role that creates the databases and users. It
doesn't need to be a superuser, just a role that can create roles and
databases:

```sql
CREATE ROLE nellie_admin LOGIN CREATEROLE CREATEDB PASSWORD 'something-long';
```

The server has to run Postgres 15 or newer. nellie checks this and tells you
if it isn't.

## Telling nellie where to go

nellie looks for the admin connection in this order:

1. `DATABASE_URL`
2. the standard Postgres variables (`PGHOST`, `PGUSER`, …) and `~/.pgpass`,
   same as `psql`
3. if neither is set, it asks, and hides what you type, since the URL
   usually contains a password

There is no `--dsn` flag on purpose: a connection string on the command line
ends up in your shell history and the process list, and that string holds the
admin password.

To skip the question, put the URL in a `.env` file in the directory you run
nellie from:

```bash
cp .env.example .env
```

```
DATABASE_URL=postgres://nellie_admin:something-long@localhost:5432/postgres
```

Anything already set in your shell wins over `.env`, so a one-off
`DATABASE_URL=... nellie add-project` still works. `PG*` and `SSL_CERT_*`
variables are ignored in `.env`, with a warning, so a checked-out `.env` can't
point nellie at another server. Set those in your shell.

One thing to know: `PGPASSWORD` from your shell is used with whatever host the
connection URL names. If you run nellie in a checkout whose `.env` you don't
trust, that URL could name another host. Check `.env` first, or keep the
password out of your shell.

### TLS

The admin connection requires TLS unless the connection string sets `sslmode`.
Postgres's own default would quietly fall back to plaintext, which would send
the admin password unencrypted. `sslmode=require` encrypts but doesn't check the
server's certificate; use `sslmode=verify-full` with a trusted CA for that.

For a local server without TLS, say so explicitly:

```
DATABASE_URL=postgres://nellie_admin:something-long@localhost:5432/postgres?sslmode=disable
```

`sslmode=prefer` and an empty `sslmode` are treated the same as `require`: a
server without TLS is an error, not a silent downgrade. `sslmode=allow` is
refused, since it tries plaintext first. Unix sockets don't use TLS, so they're
not affected. The app URLs nellie prints repeat the admin's `sslmode`, so the
app never connects with weaker TLS.

## Commands

### `nellie add-project`

Asks for a name, then creates:

- a database with that name;
- a login role with the same name that owns the database and its public
  schema, and can do everything in it.

Every privilege is revoked from `PUBLIC` on the new database, so other roles on
the server can't connect to it or create temporary tables in it. Other databases
on the server, such as `postgres`, stay open to every role, as in plain
Postgres; nellie doesn't change them.

Project names are lowercase letters, digits and `_`, start with a letter,
and are at most 57 characters long, so that every user name nellie suggests
still fits within Postgres's 63-character limit. `pg` is refused, because its
users would be named `pg_...`, a prefix Postgres reserves.

### `nellie add-user`

Asks for the project, then lets you pick a user type with the arrow keys:

```
User type (↑/↓, Enter)
> Application  reads and writes rows, can't change the schema
  Admin        can do everything, like the owner
```

Then the name. It always starts with the project name and an underscore, and
that part is fixed. You only edit what comes after it:

```
User name: shop_app
```

- **Application** users can `SELECT`, `INSERT`, `UPDATE` and `DELETE`. That
  covers tables that exist now and tables the owner creates later. They can't
  create, alter, drop or truncate anything.
- **Admin** users act as the owner as soon as they log in. That means tables
  they create belong to the owner, so your application users can still see
  them.

> **Run migrations as the owner or an admin user.** Application users only get
> access to tables owned by the project owner. A table created by any other
> role is invisible to them, which is a very confusing afternoon.

`add-user` also works on databases nellie didn't create, as long as the
admin role is a member of the database's owner.

### `nellie rotate-password [<user>]`

Gives a user, or a project owner, a new password. Asks for the user if you
don't name it, then for the new password:

```
New password (input hidden; empty generates one):
```

Press Enter (or pass `--generate`) and nellie generates one and prints it
once, in a connection URL (or on its own line if nellie can't tell which
project database the role belongs to).
Or type your own: it's asked twice, and never printed back. Typed passwords
are limited to printable ASCII (see [Passwords](#passwords)).

Got the password in a secrets manager? Pipe it in, one line, no confirmation:

```bash
op read op://vault/shop-app/password | nellie rotate-password shop_app
```

Piped input is only ever the password, on a single line, read until the input
ends (so close it, or press Ctrl-D if you're typing into a non-terminal like
`docker exec -i`): name the user as the argument, and
put the admin connection in `DATABASE_URL` (or `.env`, or the `PG*`
variables). Otherwise nellie stops with a usage error rather than reading
the password as something else. An empty pipe, or an empty line, is an error
rather than "generate one", because it usually means the command feeding it
failed (say, `echo "$PW"` with `PW` unset). In scripts, use `--generate`.

The old password stops working at once; sessions that are already connected
stay connected. Postgres has one password per role, so there's no overlap
window: update the app's config right after.

nellie won't touch roles that can't log in, superusers, the admin role it's
connected as, or roles with powers nellie never gives its own roles
(`CREATEROLE`, `REPLICATION`, `BYPASSRLS`, such as another admin), directly
or through membership in another role, and members of any predefined `pg_*`
role (other than `pg_database_owner`). Use `psql`'s `\password` for those.
On Postgres 16 and later the admin also needs `ADMIN OPTION` on the role,
which it has for every role it created; on Postgres 15 `CREATEROLE` is enough. If the role's `VALID UNTIL` has already
passed, nellie still sets the password but warns you, since the role can't
log in until that's cleared.

### `nellie list`

Also known as `nellie trumpet`. Shows every project the admin role can act
for, with its users:

```
blog  (owner blog)
  no users yet; add one with "nellie add-user"

shop  (owner shop)
  shop_admin  admin
  shop_app    application  VALID UNTIL has passed, so it can't log in
```

A project is any database whose owner the admin role is, or whose owner's
privileges it has through membership (the same rule `add-user` uses), so
databases nellie didn't create show up too. Its users are the login roles
named `<project>_<something>` that can connect to it. A user with the owner's
privileges is an `admin` user; anyone else is an `application` user. When
project names share a prefix, a user belongs to the longest one, so
`shop_v2_app` goes under `shop_v2`, not `shop`.

`list` only reads, and never shows passwords or connection URLs.

### Flags

| Flag | |
| --- | --- |
| `--dry-run` | Print the SQL instead of running it. Doesn't connect. Passwords show as `<redacted>`. All commands (for `list`, the one query it runs). |
| `--generate` | Generate the new password without asking. `rotate-password` only. |
| `--json` | Print the result as JSON, not together with `--dry-run`. `rotate-password`: `user`; `database` and `url` when the project database is found; `password` only if nellie generated it. `list`: an array of `{"project", "owner", "users": [{"name", "type", "expired"}]}`, where `type` is `application` or `admin`. |

Flags can go before or after the user name.

Add `-h` to any command for its help text.

## Passwords

An elephant never forgets. Nellie does, on purpose:

- Passwords are generated for you: 26 random characters (130 bits) from
  Go's `crypto/rand`. (`rotate-password` also lets you type or pipe in your
  own.)
- Generated ones are printed once, as part of a ready-to-use connection URL,
  and stored nowhere. Ones you typed are never printed.
- Typed passwords must be printable ASCII. Postgres normalizes other
  characters (SASLprep) before hashing, nellie doesn't, so a password like
  `smörgåsbord` could end up never working.
- They're hashed on your machine before being sent (SCRAM-SHA-256, the same
  trick as `psql`'s `\password`), so the plaintext never reaches the server
  or its logs.
- You can never pass a password as a flag or argument, so none end up in
  your shell history.

If something fails halfway, nellie cleans up after herself: whatever that
command had already created gets dropped, so you can just run it again.

If the cleanup fails too (the connection dropped, say), nellie says which role or
database may be left behind, so you can drop it by hand. That message also
appears when you stop a command with Ctrl-C partway through and the cleanup
can't finish; the exit code is still 130.

## Development

```bash
go build ./...
go vet ./...
go vet -tags integration ./...
gofmt -l .        # should print nothing
go test ./...     # unit tests, no database needed
```

The integration tests run against a real Postgres, because faking a database
is a great way to miss privilege bugs. Start a throwaway one, with a
non-superuser admin like the one you'd use for real:

```bash
docker run --rm -d --name nellie-pg -e POSTGRES_PASSWORD=postgres -p 55439:5432 postgres:18
```

```bash
docker exec nellie-pg psql -U postgres -c "CREATE ROLE nellie_admin LOGIN CREATEROLE CREATEDB PASSWORD 'admin'"
```

```bash
NELLIE_TEST_DSN=postgres://nellie_admin:admin@localhost:55439/postgres go test -tags integration ./...
```

Without `NELLIE_TEST_DSN` they're skipped.

## Contributing

- Conventions, the data model and the safety rules are in [CLAUDE.md](CLAUDE.md).
  AI coding agents should also read [AGENTS.md](AGENTS.md).
- Commits must be signed (`git commit -S`, or `git config commit.gpgsign true`).
- Before opening a PR, run the checks from the Development section above:
  `go build ./...`, `go vet ./...`, `go vet -tags integration ./...`,
  `go test ./...` and `gofmt -l .` (which must print nothing).

## Why "nellie"?

Named after *Nellie the Elephant*, by way of the Toy Dolls' punk cover. She
left the circus. This tool helps your projects leave your to-do list.

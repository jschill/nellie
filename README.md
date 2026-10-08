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

Everything is asked for interactively, so there are no flags to look up.
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

1. the `--dsn` flag
2. `DATABASE_URL`
3. the standard Postgres variables (`PGHOST`, `PGUSER`, …) and `~/.pgpass`,
   same as `psql`
4. if none of those are set, it asks, and hides what you type, since the URL
   usually contains a password

To skip the question, put the URL in a `.env` file in the directory you run
nellie from:

```bash
cp .env.example .env
```

```
DATABASE_URL=postgres://nellie_admin:something-long@localhost:5432/postgres
```

Anything already set in your shell wins over `.env`, so a one-off
`DATABASE_URL=... nellie add-project` still works.

## Commands

### `nellie add-project`

Asks for a name, then creates:

- a database with that name;
- a login role with the same name that owns the database and its public
  schema, and can do everything in it.

`CONNECT` is revoked from `PUBLIC`, so other roles on the server can't wander
into the enclosure.

Project names are lowercase letters, digits and `_`, start with a letter,
and are at most 57 characters long, so that every user name nellie suggests
still fits within Postgres's 63-character limit.

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

### Flags

Both commands take the same two flags:

| Flag | |
| --- | --- |
| `--dsn <url>` | Admin connection string. Overrides `DATABASE_URL` and friends. |
| `--dry-run` | Print the SQL instead of running it. Doesn't connect. Passwords show as `<redacted>`. |

Add `-h` to any command for its help text.

## Passwords

An elephant never forgets. Nellie does, on purpose:

- Passwords are generated for you: 26 random characters (130 bits) from
  Go's `crypto/rand`.
- They're printed once, as part of a ready-to-use connection URL, and stored
  nowhere.
- They're hashed on your machine before being sent (SCRAM-SHA-256, the same
  trick as `psql`'s `\password`), so the plaintext never reaches the server
  or its logs.
- You can never pass a password as a flag or argument, so none end up in
  your shell history.

If something fails halfway, nellie cleans up after herself: whatever that
command had already created gets dropped, so you can just run it again.

## Not yet

- `nellie rotate-password`, for a new password without a new user
- `nellie list`, also known as `nellie trumpet`

## Development

```bash
go build ./...
go vet ./...
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

## Why "nellie"?

Named after *Nellie the Elephant*, by way of the Toy Dolls' punk cover. She
left the circus. This tool helps your projects leave your to-do list.

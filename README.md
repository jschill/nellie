# nellie

A CLI written in Go for repeating PostgreSQL administration tasks: adding
projects (databases), adding users (roles) and managing their access.

## Install

```sh
go install github.com/jschill/nellie@latest
# or, from a checkout
go build -o nellie .
```

## Connecting

nellie connects as an administrative role (a superuser, or a role with
`CREATEDB`/`CREATEROLE` that is also a member of the project owner roles).

The connection string is taken from `--dsn` or the `NELLIE_DSN` environment
variable, either as a URL or as `key=value` pairs. Settings that are missing
fall back to the standard PostgreSQL environment variables (`PGHOST`, `PGPORT`,
`PGUSER`, `PGPASSWORD`, `PGDATABASE`, ...) and `~/.pgpass`.

```sh
export NELLIE_DSN="postgres://admin@db.example.com:5432/postgres"
nellie --dsn "host=localhost user=postgres dbname=postgres" user list
```

## Usage

```
nellie [--dsn DSN] <command> <subcommand> [flags] [args]
```

### Projects

A project is a database. When it is created, `PUBLIC` access is revoked, so
only the owner and users granted access with `nellie user grant` can connect.

| Command | Description |
| --- | --- |
| `nellie project add <name> [--owner ROLE]` | Create a project database, optionally owned by an existing role |
| `nellie project list` | List project databases and their owners |
| `nellie project remove <name> [--force]` | Drop a project database (`--force` terminates open connections, PostgreSQL 13+) |

### Users

| Command | Description |
| --- | --- |
| `nellie user add <name> [-W \| --password-stdin] [--createdb] [--nologin]` | Create a user, optionally with a password |
| `nellie user list` | List users (predefined `pg_*` roles are hidden) |
| `nellie user remove <name>` | Drop a user |
| `nellie user passwd <name> [--password-stdin]` | Change a user's password (prompts if `--password-stdin` is not given) |
| `nellie user lock <name>` / `nellie user unlock <name>` | Disable / enable login for a user |
| `nellie user grant <user> <project> [--readonly] [--schema NAME]` | Give a user read-write (default) or read-only access to a project |
| `nellie user revoke <user> <project> [--schema NAME]` | Remove the access given by `grant` |

`grant` gives access to all existing tables and sequences in the schema
(`public` by default). It also sets default privileges so that tables the
project owner creates later are covered too. Read-write access also allows
creating objects in the schema.

Passwords are never accepted as command line arguments. Use the `-W` prompt or
pipe them in with `--password-stdin`. nellie hashes passwords with
SCRAM-SHA-256 before sending them, so the plaintext never reaches the server or
its logs.

### Example

```sh
nellie user add shop_owner
nellie project add shop --owner shop_owner
echo "$BOB_PASSWORD" | nellie user add bob --password-stdin
nellie user grant bob shop
nellie user add reporting -W
nellie user grant --readonly reporting shop
```

## Development

```sh
go vet ./...
go test ./...
```

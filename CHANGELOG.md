# Changelog

All notable changes to nellie are listed here, newest first. The version lives
in `VERSION`; releases are tagged `vMAJOR.MINOR.PATCH`.

## [0.2.0.0] - 2026-10-09

*New trunk, same elephant: Nellie can now change the lock on the circus door
without packing anyone off.*

### Added

- `nellie rotate-password [<user>]`: give a user, or a project owner, a new
  password. Press Enter and nellie generates one and shows it once in a
  connection URL. Or type your own: it's asked twice, hidden, and never
  printed back. The old password stops working at once; sessions already
  connected stay connected.
- Pipe a password in from a secrets manager:
  `op read op://vault/shop-app/password | nellie rotate-password shop_app`.
  Piped input is only ever the password, on one non-empty line. Give the user
  as the argument and the admin connection in `DATABASE_URL`, `.env` or `PG*`,
  or nellie stops with a usage error instead of reading your password as
  something else.
- `--generate` makes a password without asking, for scripts and CI.
- `--json` prints `user`, plus `database` and `url` when nellie finds the
  project database, plus `password` only when nellie generated it.
- `--dry-run` prints the `ALTER ROLE` with the password as `<redacted>`.
  Flags can go before or after the user name.
- nellie won't rotate roles that can't log in, superusers, the admin it's
  connected as, or roles with powers nellie never hands out (`CREATEROLE`,
  `REPLICATION`, `BYPASSRLS`, directly or through membership, or any
  predefined `pg_*` role). Those are a job for `psql`'s `\password`.
- If a role's `VALID UNTIL` has already passed, nellie still sets the password
  but warns you, with the statement that clears it.
- If the result can't be written (a full disk, a closed pipe), nellie says the
  password changed but couldn't be shown, and exits 1, instead of losing a
  generated password without a word.

## [0.1.0.0] - 2026-10-09

*Nellie packed her trunk and said goodbye to the circus. Off she went with a
trumpety-trump.*

### Added

- `nellie add-project`: give it a name and it makes a database and a login role
  of the same name that owns it and can do everything in it, migrations
  included. Everyone else (`PUBLIC`) is shown the door, so nobody sneaks in or
  makes temp tables.
- `nellie add-user`: add a user to a project, picked from an arrow-key menu.
  - **Application** users can read and write rows, on tables that exist now and
    tables the owner creates later, but can't change the schema.
  - **Admin** users act as the owner, so whatever they create stays visible to
    the application users.
  - Names are always `<project>_<suffix>`; only the suffix is yours to change.
  - It works on databases nellie didn't create, as long as your admin role is a
    member of their owner.
- Passwords are generated for you and shown once, inside a ready-to-use
  connection URL. They are sent to Postgres as SCRAM-SHA-256 verifiers, so the
  plain text never reaches the server logs.
- `--dry-run` on both commands prints the SQL without touching anything. The
  password shows as `<redacted>`, and the script says it isn't meant to be run
  as is.
- Connect with `DATABASE_URL`, the usual `PG*` variables or `~/.pgpass`, or let
  nellie ask (input hidden). A `.env` file in the current directory works too;
  the shell wins, and `PG*` and `SSL_CERT_*` keys in `.env` are ignored with a
  warning.
- TLS is required by default, so a server without it is an error, not a quiet
  downgrade. `sslmode=disable` is honoured when you ask for it.
- `nellie --version` tells you which nellie you've got.
- If a command fails halfway, it tidies up after itself. If the tidying fails
  too, even after a Ctrl-C, nellie says which role or database may be left
  behind, and the first Ctrl-C tells you what is being undone. Exit code 130
  stays 130.
- Project names that would make every user name invalid (`pg`) are refused up
  front, along with anything that isn't lowercase letters, digits and
  underscores.
- Needs Postgres 15 or newer and an admin role with `CREATEROLE` and
  `CREATEDB`; a superuser is not required.

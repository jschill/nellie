# Changelog

All notable changes to nellie are listed here, newest first. The version lives
in `VERSION`; releases are tagged `vMAJOR.MINOR.PATCH`.

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

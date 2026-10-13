# Changelog

All notable changes to nellie are listed here, newest first. The version lives
in `VERSION`; releases are tagged `vMAJOR.MINOR.PATCH`.

## [0.3.0.0] - 2026-10-11

*Nellie lifts her trunk and trumpets the whole circus: every tent, every
performer, and who's been sneaking into the elephant enclosure.*

### Added

- `nellie list` (or `nellie trumpet`): every project the admin role can act
  for, with its users and their type (`application`, `admin` or
  `privileged`). It also works for databases nellie didn't create.
- `list` points out what deserves a second look: users with powers beyond
  their project (`SUPERUSER`, `CREATEROLE`, `CREATEDB`, `REPLICATION`,
  `BYPASSRLS`, predefined `pg_*` roles, owning another database), owners with
  such powers, owners not named after their database, template databases,
  users that can't connect, and expired passwords.
- Users are placed by name alone, under the longest database their name
  matches, so a project owner can't move other roles around by granting
  `CONNECT`. A user whose own database the admin can't see is shown under
  the closest project with a `belongs to database ...` note instead of
  disappearing.
- `list --json` for scripts: one object per project with its owner, flags and
  users, including whether each user is a member of the owner. `--dry-run` prints the query it would run.
- `rotate-password` warns when the role has powers beyond its project or its
  project is a template, the same things `list` shows, and its `--json`
  gains `expired`, `template` and `powers`.

### Changed

- `add-project` refuses a name that would take over existing login roles
  (with a role `shop_v2_app` around, there's no project `shop_v2`), and
  `add-user` refuses a name a longer database would claim. Projects tell
  their users apart by name, so overlapping names would mix them up.
- `rotate-password` picks the project by name the same way `list` does, and
  only prints a connection URL for a database owned by the role named after
  it, which is how nellie sets projects up.
- Every command now refuses a connection where the session acts as another
  role than the admin (for example through a database's `SET role`), instead
  of quietly doing less than you asked.
- `.env` only sets `DATABASE_URL` now; anything else in it is ignored with a
  warning. A `DATABASE_URL` from `.env` must contain its own password and
  name a single host, may only set the host, port, user, password, database,
  `sslmode` and `connect_timeout`, and nellie prints the user, host, port and database it points at.
  A checked-out `.env` can't get your admin password, client certificate or
  other `PG*` settings sent to a server of its choosing (it can still choose
  the server, so check the printed host). Set `DATABASE_URL` in your shell if
  you need more.
- If you export any `PG*` variable (even just `PGPASSWORD`) and also keep a
  `DATABASE_URL` in `.env`, nellie now refuses until you unset one of them.
- `rotate-password` only changes the passwords of the owners and users of
  the admin's projects; a user counts when its name belongs to a project
  owned by the role named after it. On Postgres 15 it could otherwise reach
  any ordinary role on the server. A failed check after the change is a
  warning, and Ctrl-C after it exits 130 with the result still printed.
- Piped `rotate-password` needs the admin connection from your shell, not
  `.env`.
- `add-project` and `add-user` wait for each other, and say so, so two runs
  at once can't both pass the name checks.
- Users that `add-user` creates in a database whose owner isn't named after
  it can't be rotated by nellie; use `psql`'s `\password` for those.
- `add-user` says so when the admin is a member of a project's owner but
  doesn't inherit its privileges (`NOINHERIT`, or a grant `WITH INHERIT
  FALSE`), with the fix for your Postgres version, instead of claiming it
  isn't a member.

### Fixed

- Errors quote role and database names, and escape control characters in
  what the server says (and indent its extra lines), so neither can scribble
  on your terminal or pose as nellie's own output.
- A `.env` saved with a byte order mark no longer loses its first line.
- `nellie help` works next to a broken `.env`, like `--version`.
- `--json` escapes non-printing characters such as U+202E, which
  `encoding/json` leaves as they are.

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

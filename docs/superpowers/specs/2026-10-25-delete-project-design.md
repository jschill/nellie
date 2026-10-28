# Delete project

Approved behavior: delete a project's database and all its project roles after
showing the target and requiring the exact project name as confirmation.

## Command

`nellie delete-project [<project>]` uses the existing connection precedence,
name validation, prompts, and exit codes. Without an argument it asks for the
name. `--dry-run` connects to read catalogs and prints the actual drop statements
without changing anything or requiring confirmation. No force flag or bypass.

## Selection and safeguards

The database must be owned by the role named after it and the admin must inherit
that owner's privileges. Refuse templates, postgres, template0, template1, and
the current connection database. Select roles, including NOLOGIN roles, by the
longest matching database name. Preserve longer overlapping projects. Refuse the
admin itself, outside powers, outside dependencies, and insufficient role-drop
privileges before dropping the database.

Keep SQL in internal/pg and CLI interaction in internal/cli. Hold the same
session advisory lock as add-project/add-user while planning, confirming, and
deleting. Recheck after confirmation and reject changed targets. External tools
do not honor the advisory lock; concurrent manual catalog changes remain outside
its protection.

## Execution and errors

Drop the database without terminating sessions. PostgreSQL cannot do this in a
transaction. Then protect and drop the selected roles together in one
transaction: use ALTER ROLE ... NOLOGIN to hold catalog row locks, verify the
planned OIDs and current powers, and drop them only if all checks pass. Failed
cleanup rolls back the login changes. The dry-run script shows these updates
and identity queries, but is for inspection; Go enforces the identity and power
checks. Never use DROP OWNED across databases. If role cleanup fails or is interrupted, explicitly
report that the database was deleted and list the roles that may remain. A
cancelled database drop must report its uncertain outcome. Ctrl-C during the
confirmation must exit without deleting anything. A failed warning, role-list,
or confirmation-prompt write must abort before any destructive statement.

## Validation

Use failing tests before implementation. Exercise CLI help and validation,
real PostgreSQL confirmation/dry-run behavior, role cleanup, unsafe targets,
external dependencies, active sessions, overlapping names, catalog changes while
confirming, and interruption. Run build, unit tests, the full non-superuser
integration suite, relevant superuser cases, vet in both builds, and gofmt.

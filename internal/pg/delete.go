package pg

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Deletion describes the database and roles to remove. Roles are sorted by name.
type Deletion struct {
	Project     string
	Roles       []string
	databaseOID uint32 // detect objects replaced during confirmation
	roleOIDs    []uint32
}

// Script prints the destructive statements. DROP DATABASE cannot be transactional;
// the role drops are a single transaction so they either all succeed or all remain.
func (d Deletion) Script() string {
	var b strings.Builder
	b.WriteString("-- dry run: role identities and powers are checked by nellie; this script is for inspection only\n")
	fmt.Fprintf(&b, "%s;\nDROP DATABASE %s;\nBEGIN;\n", pinSearchPath, ident(d.Project))
	for i, role := range d.Roles {
		fmt.Fprintf(&b, "ALTER ROLE %s NOLOGIN;\n", ident(role))
		fmt.Fprintf(&b, "SELECT oid FROM pg_roles WHERE rolname = %s; -- expected OID %d\n", literal(role), d.roleOIDs[i])
	}
	for _, role := range d.Roles {
		fmt.Fprintf(&b, "DROP ROLE %s;\n", ident(role))
	}
	b.WriteString("COMMIT;\n")
	return b.String()
}

// DeleteProject previews a deletion through confirm before executing it. A dry run
// reads catalogs but changes nothing. A live run holds the same lock as add-* until
// it finishes, including while confirm asks the user. confirm must not be nil.
func DeleteProject(ctx context.Context, cfg *pgx.ConnConfig, name string, dryRun bool, confirm func(Deletion) error) error {
	if err := ValidateProjectName(name); err != nil {
		return err
	}
	if confirm == nil {
		return fmt.Errorf("project deletion requires confirmation")
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}
	defer conn.Close(context.Background())
	if err = pinSession(ctx, conn); err != nil {
		return err
	}
	if err = checkServerVersion(ctx, conn); err != nil {
		return err
	}
	if !dryRun {
		if err = lockAdd(ctx, conn); err != nil {
			return err
		}
	}
	plan, err := deletionPlan(ctx, conn, name)
	if err != nil {
		return err
	}
	if err = confirm(plan); err != nil {
		return err
	}
	if dryRun {
		return nil
	}
	// Recheck after the human has answered: external tools don't take nellie's lock.
	fresh, err := deletionPlan(ctx, conn, name)
	if err != nil {
		return err
	}
	if plan.databaseOID != fresh.databaseOID || !slices.Equal(plan.Roles, fresh.Roles) || !slices.Equal(plan.roleOIDs, fresh.roleOIDs) {
		return fmt.Errorf("project or roles changed during confirmation; run delete-project again")
	}
	if _, err = conn.Exec(ctx, "DROP DATABASE "+ident(name)); err != nil {
		return fmt.Errorf("dropping database %q failed (if interrupted, verify whether it still exists); roles were not dropped: %w", name, err)
	}
	if err = dropProjectRoles(ctx, conn, plan); err != nil {
		return fmt.Errorf("database %q was deleted; dropping roles failed, roles may remain %q: %w", name, plan.Roles, err)
	}
	return nil
}

// Updating each role holds its catalog row until commit. Unlike a SELECT followed
// by DROP ROLE, this prevents a role from being renamed or replaced after its OID
// is checked. The update also waits for conflicting catalog locks before the
// check, so a replacement created while we waited is detected and rolled back.
// NOLOGIN is transactional: failures restore every surviving role's login state.
func dropProjectRoles(ctx context.Context, conn *pgx.Conn, plan Deletion) error {
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		for i, role := range plan.Roles {
			if _, err := tx.Exec(ctx, "ALTER ROLE "+ident(role)+" NOLOGIN"); err != nil {
				return fmt.Errorf("protecting role %q during cleanup: %w", role, err)
			}
			var oid uint32
			if err := tx.QueryRow(ctx, "SELECT oid FROM pg_roles WHERE rolname = $1", role).Scan(&oid); err != nil {
				return fmt.Errorf("checking role %q during cleanup: %w", role, err)
			}
			if oid != plan.roleOIDs[i] {
				return fmt.Errorf("role %q changed during cleanup; refusing to drop its replacement", role)
			}
			// The project database is gone now. Check for powers elsewhere again
			// after protecting the role, in case they changed while we waited.
			powers, err := rolePowers(ctx, tx.Conn(), role, "")
			if err != nil {
				return err
			}
			if len(powers) != 0 {
				return fmt.Errorf("refusing to delete role %q with powers outside the project: %s", role, strings.Join(powers, ", "))
			}
		}
		for _, role := range plan.Roles {
			if _, err := tx.Exec(ctx, "DROP ROLE "+ident(role)); err != nil {
				return err
			}
		}
		return nil
	})
}

func deletionPlan(ctx context.Context, conn *pgx.Conn, name string) (Deletion, error) {
	plan := Deletion{Project: name}
	var oid uint32
	var owner, currentDB string
	var template, allowed bool
	err := conn.QueryRow(ctx, `SELECT d.oid, pg_get_userbyid(d.datdba), current_database(), d.datistemplate,
 `+isProjectExpr+` FROM pg_database d WHERE d.datname=$1`, name).Scan(&oid, &owner, &currentDB, &template, &allowed)
	if err == pgx.ErrNoRows {
		return plan, fmt.Errorf("database %q %w", name, ErrNotFound)
	}
	if err != nil {
		return plan, fmt.Errorf("looking up project: %w", err)
	}
	plan.databaseOID = oid
	if name == currentDB || name == "postgres" || name == "template0" || name == "template1" {
		return plan, fmt.Errorf("refusing to delete protected or current connection database %q; connect to another database", name)
	}
	if !allowed || owner != name || template {
		return plan, fmt.Errorf("refusing to delete database %q: it must be a non-template project owned by the role named after it, whose privileges the admin inherits", name)
	}
	rows, err := conn.Query(ctx, `SELECT r.rolname, r.oid FROM pg_roles r
 WHERE (SELECT d.datname FROM pg_database d
 WHERE r.rolname=d.datname OR starts_with(r.rolname,d.datname || '_')
 ORDER BY length(d.datname) DESC LIMIT 1)=$1 ORDER BY r.rolname`, name)
	if err != nil {
		return plan, fmt.Errorf("looking up project roles: %w", err)
	}
	for rows.Next() {
		var role string
		var roleOID uint32
		if err := rows.Scan(&role, &roleOID); err != nil {
			rows.Close()
			return plan, fmt.Errorf("reading project roles: %w", err)
		}
		plan.Roles = append(plan.Roles, role)
		plan.roleOIDs = append(plan.roleOIDs, roleOID)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return plan, fmt.Errorf("reading project roles: %w", err)
	}
	for _, role := range plan.Roles {
		var self bool
		if err = conn.QueryRow(ctx, "SELECT $1::name IN (current_user,session_user)", role).Scan(&self); err != nil {
			return plan, err
		}
		if self {
			return plan, fmt.Errorf("refusing to delete admin role %q", role)
		}
		powers, e := rolePowers(ctx, conn, role, name)
		if e != nil {
			return plan, e
		}
		if len(powers) > 0 {
			return plan, fmt.Errorf("refusing to delete role %q with powers outside the project: %s", role, strings.Join(powers, ", "))
		}
		var dependencies bool
		err = conn.QueryRow(ctx, `WITH RECURSIVE reachable(oid) AS (
   SELECT oid FROM pg_roles WHERE rolname=$1
   UNION
   SELECT m.roleid FROM pg_auth_members m JOIN reachable r ON m.member=r.oid
 )
 SELECT EXISTS(SELECT FROM pg_shdepend s
   WHERE s.refclassid='pg_authid'::regclass AND s.refobjid IN (SELECT oid FROM reachable)
   AND s.dbid<>$2 AND NOT(s.dbid=0 AND s.classid='pg_database'::regclass AND s.objid=$2))`, role, oid).Scan(&dependencies)
		if err != nil {
			return plan, fmt.Errorf("checking dependencies of role %q: %w", role, err)
		}
		if dependencies {
			return plan, fmt.Errorf("refusing to delete role %q: it has dependencies outside project %q", role, name)
		}
		var canDrop bool
		err = conn.QueryRow(ctx, `SELECT a.rolsuper OR (a.rolcreaterole AND
   (current_setting('server_version_num')::int<160000 OR EXISTS(
    SELECT FROM pg_auth_members m WHERE m.roleid=r.oid AND m.member=a.oid AND m.admin_option)))
   FROM pg_roles a,pg_roles r WHERE a.rolname=current_user AND r.rolname=$1`, role).Scan(&canDrop)
		if err != nil {
			return plan, err
		}
		if !canDrop {
			return plan, fmt.Errorf("admin cannot drop role %q: CREATEROLE and, on PostgreSQL 16+, ADMIN OPTION are required", role)
		}
	}
	return plan, nil
}

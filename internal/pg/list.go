package pg

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// pinSearchPath runs before ListSQL. The query uses catalogs and functions by
// unqualified name, which the owner of the connection database could shadow
// through its search_path (see RotatePassword).
const pinSearchPath = "SET search_path = pg_catalog, pg_temp"

// ListSQL is the query behind nellie list. It has no bind parameters, so
// --dry-run can print exactly what runs (see ListScript).
//
// projects: databases whose owner's privileges the admin role has, through
// membership or by owning them directly: the same check as add-user. Not
// 'MEMBER': on Postgres 16+ a CREATEROLE admin keeps an ADMIN-only membership
// in every role it created, which counts as MEMBER but can't act as the role.
// Templates, databases that allow no connections and invalid ones
// (datconnlimit -2, a DROP DATABASE that was interrupted) are left out.
//
// users: login roles that can connect to the project, named <project>_<something>.
// A role that matches several projects belongs to the longest one, and a role
// named like a project belongs to that project, as in rotate-password's
// projectCandidates: DISTINCT ON keeps the first row per role, and the
// ORDER BY puts the longest project name first. That project's owner is
// shown as the owner, so the outer WHERE drops it from the users. Superusers
// and the admin role itself are no project's users, so they're left out.
//
// Any member of the owner is an admin user (see User.Plan), here 'MEMBER' on
// purpose: a NOINHERIT member doesn't use the owner's privileges directly,
// but can SET ROLE to the owner whenever it likes.
//
// The LEFT JOIN keeps projects without users, as a row with empty user columns.
const ListSQL = `WITH projects AS (
	SELECT oid, datname, datdba FROM pg_database
	WHERE NOT datistemplate AND datallowconn AND datconnlimit <> -2
		AND pg_has_role(datdba, 'USAGE')
), users AS (
	SELECT project, rolname, admin, expired FROM (
		SELECT DISTINCT ON (r.rolname) p.oid AS project, p.datname, r.rolname,
			pg_has_role(r.oid, p.datdba, 'MEMBER') AS admin,
			coalesce(r.rolvaliduntil < now(), false) AS expired
		FROM pg_roles r
		JOIN projects p ON r.rolname = p.datname OR starts_with(r.rolname, p.datname || '_')
		WHERE r.rolcanlogin AND NOT r.rolsuper
			AND r.rolname NOT IN (current_user, session_user)
			AND has_database_privilege(r.oid, p.oid, 'CONNECT')
		ORDER BY r.rolname, length(p.datname) DESC
	) matched
	WHERE rolname <> datname
)
SELECT p.datname, pg_get_userbyid(p.datdba),
	coalesce(u.rolname, ''), coalesce(u.admin, false), coalesce(u.expired, false)
FROM projects p LEFT JOIN users u ON u.project = p.oid
ORDER BY p.datname, u.rolname`

// ListScript is what ListProjects runs, as a psql script for --dry-run.
func ListScript() string {
	return pinSearchPath + ";\n" + ListSQL + ";\n"
}

// ProjectInfo is a project as nellie list shows it.
type ProjectInfo struct {
	Name  string // the database
	Owner string // the role that owns it
	Users []UserInfo
}

// UserInfo is a project user as nellie list shows it.
type UserInfo struct {
	Name string
	Kind UserKind
	// Expired means the role's VALID UNTIL has passed, so it can't log in.
	Expired bool
}

// ListProjects returns the projects the admin role in cfg can act for, sorted
// by name, each with its users sorted by name. It only reads catalogs.
func ListProjects(ctx context.Context, cfg *pgx.ConnConfig) ([]ProjectInfo, error) {
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connecting: %w", err)
	}
	defer conn.Close(context.Background())

	if _, err := conn.Exec(ctx, pinSearchPath); err != nil {
		return nil, fmt.Errorf("setting search_path: %w", err)
	}
	if err := checkServerVersion(ctx, conn); err != nil {
		return nil, err
	}

	rows, err := conn.Query(ctx, ListSQL)
	if err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}
	defer rows.Close()

	var projects []ProjectInfo
	for rows.Next() {
		var db, owner, user string
		var admin, expired bool
		if err := rows.Scan(&db, &owner, &user, &admin, &expired); err != nil {
			return nil, fmt.Errorf("listing projects: %w", err)
		}
		// Rows come sorted by project, so a new name starts a new project.
		if len(projects) == 0 || projects[len(projects)-1].Name != db {
			projects = append(projects, ProjectInfo{Name: db, Owner: owner})
		}
		if user == "" {
			continue // a project without users
		}
		kind := AppUser
		if admin {
			kind = AdminUser
		}
		p := &projects[len(projects)-1]
		p.Users = append(p.Users, UserInfo{Name: user, Kind: kind, Expired: expired})
	}
	// rows.Next returns false on errors too, not only at the end.
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}
	return projects, nil
}

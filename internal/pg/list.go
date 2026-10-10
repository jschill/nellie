package pg

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ListSQL is the query behind nellie list. It has no bind parameters, so
// --dry-run can print exactly what runs.
//
// projects: databases whose owner's privileges the admin role has, through
// membership or by owning them directly: the same check as add-user. Not
// 'MEMBER': on Postgres 16+ a CREATEROLE admin keeps an ADMIN-only membership
// in every role it created, which counts as MEMBER but can't act as the role.
// Templates and invalid databases (datconnlimit -2, a DROP DATABASE that was
// interrupted) are left out.
//
// users: login roles named <project>_<something> that can connect to the
// project. A role that matches several projects belongs to the longest one,
// as in rotate-password: DISTINCT ON keeps the first row per role, and the
// ORDER BY puts the longest project name first. A user that has the owner's
// privileges is an admin user (see User.Plan).
//
// The LEFT JOIN keeps projects without users, as a row with empty user columns.
const ListSQL = `WITH projects AS (
	SELECT oid, datname, datdba FROM pg_database
	WHERE NOT datistemplate AND datconnlimit <> -2
		AND pg_has_role(datdba, 'USAGE')
), users AS (
	SELECT DISTINCT ON (r.rolname) p.oid AS project, r.rolname,
		pg_has_role(r.oid, p.datdba, 'USAGE') AS admin,
		coalesce(r.rolvaliduntil < now(), false) AS expired
	FROM pg_roles r
	JOIN projects p ON starts_with(r.rolname, p.datname || '_')
	WHERE r.rolcanlogin AND has_database_privilege(r.oid, p.oid, 'CONNECT')
	ORDER BY r.rolname, length(p.datname) DESC
)
SELECT p.datname, pg_get_userbyid(p.datdba),
	coalesce(u.rolname, ''), coalesce(u.admin, false), coalesce(u.expired, false)
FROM projects p LEFT JOIN users u ON u.project = p.oid
ORDER BY p.datname, u.rolname`

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

	// As in RotatePassword: the query uses catalogs and functions by
	// unqualified name, which the owner of the connection database could
	// shadow through its search_path.
	if _, err := conn.Exec(ctx, "SET search_path = pg_catalog, pg_temp"); err != nil {
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

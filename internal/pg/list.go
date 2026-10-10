package pg

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ListSQL is the query behind nellie list. It has no bind parameters, so
// --dry-run can print exactly what runs (see ListScript).
//
// projects: databases whose owner's privileges the admin role has, through
// membership or by owning them directly: the same check as add-user. Not
// 'MEMBER': on Postgres 16+ a CREATEROLE admin keeps an ADMIN-only membership
// in every role it created, which counts as MEMBER but can't act as the role.
// Templates and databases that allow no connections are kept on purpose:
// their owner can switch either setting, so filtering on them would let the
// owner hide a project. Left out are invalid ones (datconnlimit -2, an
// interrupted DROP DATABASE) and, by name, Postgres's own template0 and
// template1, which a superuser admin would otherwise see as projects.
//
// users: login roles named <project>_<something> (or exactly like a database,
// as in rotate-password's projectCandidates) that can connect to it or are a
// member of its owner; the owner controls CONNECT, so CONNECT alone would let
// it hide its admin users. A role belongs to the longest matching database,
// searched among all of them: DISTINCT ON keeps the first row per role, and
// the ORDER BY puts the longest database name first. Only then are roles
// whose database isn't one of the projects dropped (by the LEFT JOIN), so a
// role of a project the admin can't see doesn't fall through to a shorter
// one. The owner is shown as the owner, so the outer WHERE drops it, by OID,
// from the users. The admin role itself is no project's user.
//
// Any member of the owner is an admin user (see User.Plan), here 'MEMBER' on
// purpose, erring towards admin: a NOINHERIT member doesn't use the owner's
// privileges directly but can SET ROLE to the owner, and the rare Postgres 16+
// grant with neither INHERIT nor SET still ties the role to the owner.
//
// powers lists what makes a user privileged, the same things rotate-password
// refuses: SUPERUSER, CREATEROLE, REPLICATION, BYPASSRLS, and membership in a
// role that has them or in a predefined pg_* role (except pg_database_owner).
//
// The LEFT JOIN keeps projects without users, as a row with empty user columns.
const ListSQL = `WITH projects AS (
	SELECT oid, datname, datdba FROM pg_database
	WHERE datconnlimit <> -2 AND datname NOT IN ('template0', 'template1')
		AND pg_has_role(datdba, 'USAGE')
), users AS (
	SELECT project, rolname, admin, powers, expired FROM (
		SELECT DISTINCT ON (r.rolname) d.oid AS project, d.datdba, r.oid AS role, r.rolname,
			pg_has_role(r.oid, d.datdba, 'MEMBER') AS admin,
			concat_ws(', ',
				CASE WHEN r.rolsuper THEN 'SUPERUSER' END,
				CASE WHEN r.rolcreaterole THEN 'CREATEROLE' END,
				CASE WHEN r.rolreplication THEN 'REPLICATION' END,
				CASE WHEN r.rolbypassrls THEN 'BYPASSRLS' END,
				(SELECT 'member of ' || string_agg(g.rolname, ', ' ORDER BY g.rolname) FROM pg_roles g
					WHERE NOT r.rolsuper -- a superuser is a member of every role
						AND g.oid <> r.oid AND pg_has_role(r.oid, g.oid, 'MEMBER')
						AND (g.rolsuper OR g.rolcreaterole OR g.rolreplication OR g.rolbypassrls
							OR (starts_with(g.rolname, 'pg_') AND g.rolname <> 'pg_database_owner')))
			) AS powers,
			coalesce(r.rolvaliduntil < now(), false) AS expired
		FROM pg_roles r
		JOIN pg_database d ON r.rolname = d.datname OR starts_with(r.rolname, d.datname || '_')
		WHERE r.rolcanlogin AND d.datconnlimit <> -2
			AND r.rolname NOT IN (current_user, session_user)
			AND (has_database_privilege(r.oid, d.oid, 'CONNECT') OR pg_has_role(r.oid, d.datdba, 'MEMBER'))
		ORDER BY r.rolname, length(d.datname) DESC
	) matched
	WHERE role <> datdba
)
SELECT p.datname, pg_get_userbyid(p.datdba), coalesce(u.rolname, ''),
	coalesce(u.admin, false), coalesce(u.powers, ''), coalesce(u.expired, false)
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
	// Powers is what makes the user privileged, such as "CREATEROLE" or
	// "member of pg_monitor", or "" for none.
	Powers string
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

	if err := pinSession(ctx, conn); err != nil {
		return nil, err
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
		var db, owner, user, powers string
		var admin, expired bool
		if err := rows.Scan(&db, &owner, &user, &admin, &powers, &expired); err != nil {
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
		p.Users = append(p.Users, UserInfo{Name: user, Kind: kind, Powers: powers, Expired: expired})
	}
	// rows.Next returns false on errors too, not only at the end.
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}
	return projects, nil
}

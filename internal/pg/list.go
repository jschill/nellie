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
// Templates and databases closed to connections are kept on purpose: their
// owner can switch either setting, so filtering on them would let the owner
// hide a project. Left out are invalid databases (datconnlimit -2, an
// interrupted DROP DATABASE) and, by name, Postgres's own template0 and
// template1, which a superuser admin would otherwise see as projects.
//
// users: login roles named <db>_<something>, or exactly <db>. Names alone
// decide where a role goes: the longest matching database, among all of
// them (DISTINCT ON keeps the first row per role; the ORDER BY puts the
// longest name first). Access must not decide it, because a database's owner
// controls who may connect to it, and could pull a role into its database or
// push one out. Creating a database to match a name needs CREATEDB. Whether
// the role can connect is reported instead (can_connect). A role whose
// database isn't one of the projects isn't listed at all, so it can't fall
// through to a shorter project. The owner is shown as the owner, so the JOIN
// drops it, by OID, from the users. The admin role itself is no project's user.
//
// Any member of the owner is an admin user (see User.Plan), here 'MEMBER' on
// purpose, erring towards admin: a NOINHERIT member doesn't use the owner's
// privileges directly but can SET ROLE to the owner, and the rare Postgres 16+
// grant with neither INHERIT nor SET still ties the role to the owner.
//
// powers lists what makes a user privileged: what rotate-password refuses
// (SUPERUSER, CREATEROLE, REPLICATION, BYPASSRLS, membership in a role that
// has them or in a predefined pg_* role except pg_database_owner), plus
// membership in the owner of another database, which gives that project too.
//
// The LEFT JOIN keeps projects without users, as a row with empty user columns.
const ListSQL = `WITH projects AS (
	SELECT oid, datname, datdba FROM pg_database
	WHERE datconnlimit <> -2 AND datname NOT IN ('template0', 'template1')
		AND pg_has_role(datdba, 'USAGE')
), users AS (
	SELECT DISTINCT ON (r.rolname) d.oid AS project, r.oid AS role, r.rolname,
		pg_has_role(r.oid, d.datdba, 'MEMBER') AS admin,
		has_database_privilege(r.oid, d.oid, 'CONNECT') AS can_connect,
		concat_ws(', ',
			CASE WHEN r.rolsuper THEN 'SUPERUSER' END,
			CASE WHEN r.rolcreaterole THEN 'CREATEROLE' END,
			CASE WHEN r.rolreplication THEN 'REPLICATION' END,
			CASE WHEN r.rolbypassrls THEN 'BYPASSRLS' END,
			(SELECT 'member of ' || string_agg(g.rolname, ', ' ORDER BY g.rolname) FROM pg_roles g
				WHERE NOT r.rolsuper -- a superuser is a member of every role
					AND g.oid <> r.oid AND pg_has_role(r.oid, g.oid, 'MEMBER')
					AND (g.rolsuper OR g.rolcreaterole OR g.rolreplication OR g.rolbypassrls
						OR (starts_with(g.rolname, 'pg_') AND g.rolname <> 'pg_database_owner')
						OR g.oid IN (SELECT datdba FROM pg_database WHERE datdba <> d.datdba)))
		) AS powers,
		coalesce(r.rolvaliduntil < now(), false) AS expired
	FROM pg_roles r
	JOIN pg_database d ON r.rolname = d.datname OR starts_with(r.rolname, d.datname || '_')
	WHERE r.rolcanlogin AND d.datconnlimit <> -2
		AND r.rolname NOT IN (current_user, session_user)
	ORDER BY r.rolname, length(d.datname) DESC
)
SELECT p.datname, pg_get_userbyid(p.datdba), coalesce(u.rolname, ''), coalesce(u.admin, false),
	coalesce(u.can_connect, false), coalesce(u.powers, ''), coalesce(u.expired, false)
FROM projects p LEFT JOIN users u ON u.project = p.oid AND u.role <> p.datdba
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
	// CanConnect is whether the role may connect to the project's database.
	// A role that can't is still listed: who may connect is up to the owner.
	CanConnect bool
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
		var admin, canConnect, expired bool
		if err := rows.Scan(&db, &owner, &user, &admin, &canConnect, &powers, &expired); err != nil {
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
		p.Users = append(p.Users, UserInfo{Name: user, Kind: kind, Powers: powers, CanConnect: canConnect, Expired: expired})
	}
	// rows.Next returns false on errors too, not only at the end.
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}
	return projects, nil
}

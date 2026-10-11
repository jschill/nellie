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
// homes: each login role named <db>_<something>, or exactly <db>, and its
// home database: the longest one its name matches, among all of them,
// invalid ones included (DISTINCT ON keeps the first row per role; the ORDER
// BY puts the longest name first). Names alone decide this. Access must not,
// because a database's owner controls who may connect to it, and could pull
// a role into its database or push one out.
//
// users: where each role is shown. That's its home when the home is a
// project. Otherwise, so no role silently disappears (a CREATEDB role can
// create a database named like a user), it's the longest project its name
// matches, with belongs_to naming the home; that includes a role that owns
// its home. A role whose name matches no project isn't listed. The shown
// project's owner is its owner, not a user, so users drops it (by OID);
// homes already left out the admin role itself (current_user, session_user).
//
// Any member of the owner is an admin user (see User.Plan), here 'MEMBER' on
// purpose, erring towards admin: a NOINHERIT member doesn't use the owner's
// privileges directly but can SET ROLE to the owner, and the rare Postgres 16+
// grant with neither INHERIT nor SET still ties the role to the owner.
//
// can_connect: see canConnectExpr. A project is marked when it's a template
// (any CREATEDB role can copy it, data included) and when its owner isn't the
// role named after it (foreign_owner): nellie's projects always are, and only
// those get a connection URL from rotate-password.
//
// powers (see powersExpr) is computed once for every listed user and owner,
// then joined to both. The LEFT JOINs keep projects without users, as a row
// with empty user columns.
const ListSQL = `WITH projects AS (
	SELECT oid, datname, datdba, datistemplate,
		pg_get_userbyid(datdba) <> datname AS foreign_owner
	FROM pg_database d
	WHERE ` + isProjectExpr + `
), homes AS (
	SELECT DISTINCT ON (r.rolname) r.oid AS role, r.rolname,
		d.oid AS home, d.datname AS home_name
	FROM pg_roles r
	JOIN pg_database d ON r.rolname = d.datname OR starts_with(r.rolname, d.datname || '_')
	WHERE r.rolcanlogin AND r.rolname NOT IN (current_user, session_user)
	ORDER BY r.rolname, length(d.datname) DESC
), users AS (
	SELECT p.oid AS project, h.role, h.rolname,
		CASE WHEN p.oid = h.home THEN '' ELSE h.home_name END AS belongs_to
	FROM homes h
	CROSS JOIN LATERAL (
		SELECT oid, datdba FROM projects p
		WHERE h.rolname = p.datname OR starts_with(h.rolname, p.datname || '_')
		ORDER BY length(p.datname) DESC LIMIT 1
	) p
	WHERE h.role <> p.datdba
), ` + poweredCTE + `, powers AS (
	SELECT s.project, s.role, ` + powersExpr + ` AS list
	FROM (SELECT project, role FROM users UNION SELECT oid, datdba FROM projects) s
	JOIN pg_roles r ON r.oid = s.role
)
SELECT p.datname, pg_get_userbyid(p.datdba), coalesce(op.list, '{}'),
	p.datistemplate, p.foreign_owner,
	coalesce(u.rolname, ''), coalesce(u.belongs_to, ''),
	coalesce(pg_has_role(r.oid, p.datdba, 'MEMBER'), false),
	coalesce(` + canConnectExpr + `, false),
	coalesce(up.list, '{}'), coalesce(r.rolvaliduntil < now(), false)
FROM projects p
JOIN pg_database d ON d.oid = p.oid
LEFT JOIN powers op ON op.project = p.oid AND op.role = p.datdba
LEFT JOIN users u ON u.project = p.oid
LEFT JOIN pg_roles r ON r.oid = u.role
LEFT JOIN powers up ON up.project = u.project AND up.role = u.role
ORDER BY p.datname, u.rolname`

// isProjectExpr is whether database d is one of the admin's projects: the
// admin has its owner's privileges, and it's neither Postgres's own template0
// or template1 nor invalid (datconnlimit -2, left by an interrupted DROP
// DATABASE). Shared with rotate-password, so both pick the same projects.
const isProjectExpr = `d.datconnlimit <> -2 AND d.datname NOT IN ('template0', 'template1')
	AND pg_has_role(d.datdba, 'USAGE')`

// canConnectExpr is whether role r may connect to database d: the database
// allows connections (datallowconn), and, except for superusers, neither the
// database's nor the role's connection limit is 0, as well as CONNECT; the
// privilege alone ignores all three. Shared with rotate-password's URL check.
const canConnectExpr = `d.datallowconn AND (r.rolsuper OR (d.datconnlimit <> 0 AND r.rolconnlimit <> 0))
		AND has_database_privilege(r.oid, d.oid, 'CONNECT')`

// poweredCTE and powersExpr compute what makes a role privileged beyond its
// project, for ListSQL and rotate-password's warning, so the two can't drift
// apart. powersExpr needs the role's pg_roles row as r and its project's
// database OID as s.project (0 for none), with poweredCTE in the WITH.
//
// A power is what rotate-password refuses (SUPERUSER, CREATEROLE,
// REPLICATION, BYPASSRLS, membership in a role that has them or in a
// predefined pg_* role except pg_database_owner), plus CREATEDB, which could
// create a database matching a user's name, and owning another database, or
// membership in a role that owns one, which gives that project too. "Another"
// compares databases, not owners: the project's own owner may own a second
// database as well. Each power is its own array element, so a name containing
// ", " can't pass for another power. Superusers and CREATEROLE roles skip the
// memberships: a superuser is a member of every role, and a CREATEROLE role
// of every role it created, which would bury their real powers.
//
// powered narrows the roles whose membership can count to those with a power
// or owning a database, so pg_has_role runs against those only: against every
// role it took seconds on a cluster with many roles.
const poweredCTE = `powered AS MATERIALIZED (
	SELECT oid, rolname,
		rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls
			OR (starts_with(rolname, 'pg_') AND rolname <> 'pg_database_owner') AS always
	FROM pg_roles
	WHERE rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls
		OR starts_with(rolname, 'pg_') OR oid IN (SELECT datdba FROM pg_database)
)`

const powersExpr = `array_remove(ARRAY[
			CASE WHEN r.rolsuper THEN 'SUPERUSER' END,
			CASE WHEN r.rolcreaterole THEN 'CREATEROLE' END,
			CASE WHEN r.rolcreatedb THEN 'CREATEDB' END,
			CASE WHEN r.rolreplication THEN 'REPLICATION' END,
			CASE WHEN r.rolbypassrls THEN 'BYPASSRLS' END], NULL)
		|| ARRAY(SELECT 'owner of ' || o.datname FROM pg_database o
			WHERE o.datdba = r.oid AND o.oid <> s.project ORDER BY o.datname)
		|| ARRAY(SELECT 'member of ' || g.rolname FROM powered g
			WHERE NOT r.rolsuper AND NOT r.rolcreaterole
				AND g.oid <> r.oid
				AND (g.always OR g.oid IN (SELECT datdba FROM pg_database WHERE oid <> s.project))
				AND pg_has_role(r.oid, g.oid, 'MEMBER')
			ORDER BY g.rolname)`

// ListScript is what ListProjects runs, as a psql script for --dry-run.
func ListScript() string {
	return pinSearchPath + ";\n" + ListSQL + ";\n"
}

// ProjectInfo is a project as nellie list shows it.
type ProjectInfo struct {
	Name  string // the database
	Owner string // the role that owns it
	// Template means any CREATEDB role can copy the database, data included.
	Template bool
	// ForeignOwner means the owner isn't the role named after the database,
	// as it is for projects nellie creates.
	ForeignOwner bool
	// OwnerPowers is what makes the owner privileged beyond this project, as
	// for UserInfo.Powers; nil for none.
	OwnerPowers []string
	Users       []UserInfo
}

// UserInfo is a project user as nellie list shows it.
type UserInfo struct {
	Name string
	Kind UserKind
	// Powers is what makes the user privileged, one per element, such as
	// "CREATEROLE" or "member of pg_monitor"; nil for none.
	Powers []string
	// BelongsTo names the database the user's name belongs to when that isn't
	// this project: one the admin can't act for, or an invalid one. It's
	// shown under this project, the longest one its name matches, so it
	// doesn't silently disappear. "" for a user of this project.
	BelongsTo string
	// CanConnect is whether the role may connect to the project's database.
	// A role that can't is still listed: who may connect is up to the owner.
	CanConnect bool
	// Expired means the role's VALID UNTIL has passed, so its password no
	// longer works; methods without a password (peer, cert) still do.
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
		var db, owner, user, belongsTo string
		var ownerPowers, powers []string
		var template, foreignOwner, admin, canConnect, expired bool
		if err := rows.Scan(&db, &owner, &ownerPowers, &template, &foreignOwner, &user, &belongsTo, &admin, &canConnect, &powers, &expired); err != nil {
			return nil, fmt.Errorf("listing projects: %w", err)
		}
		// Rows come sorted by project, so a new name starts a new project.
		if len(projects) == 0 || projects[len(projects)-1].Name != db {
			projects = append(projects, ProjectInfo{Name: db, Owner: owner, OwnerPowers: noneIfEmpty(ownerPowers),
				Template: template, ForeignOwner: foreignOwner})
		}
		if user == "" {
			continue // a project without users
		}
		kind := AppUser
		if admin {
			kind = AdminUser
		}
		p := &projects[len(projects)-1]
		p.Users = append(p.Users, UserInfo{Name: user, Kind: kind, Powers: noneIfEmpty(powers), BelongsTo: belongsTo, CanConnect: canConnect, Expired: expired})
	}
	// rows.Next returns false on errors too, not only at the end.
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}
	return projects, nil
}

// noneIfEmpty returns nil for an empty slice, so "no powers" has one value
// (nil) whether the database sent {} or nothing.
func noneIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

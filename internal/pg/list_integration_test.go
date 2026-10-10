//go:build integration

package pg

import (
	"context"
	"crypto/rand"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Value: protects=list shows only projects the admin can act for, each with its users, their types and expiry; fails_when=a membership, CONNECT, LOGIN, template, ALLOW_CONNECTIONS, prefix, owner or type rule changes; why_new=new code; seam=none
func TestListProjects(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	p, _, dropUsers := newTestProject(t, cfg)

	// p_v2 shares p's prefix, so p_v2_app could belong to either.
	v2, err := NewProject(p.Name + "_v2")
	if err != nil {
		t.Fatal(err)
	}
	if err := CreateProject(ctx, cfg, v2, NewPassword()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := dropProject(context.Background(), cfg, v2, true); err != nil {
			t.Errorf("dropping test project: %v", err)
		}
	})

	addUser := func(kind UserKind, name, project string) {
		t.Helper()
		u, err := NewUser(kind, name, project)
		if err != nil {
			t.Fatal(err)
		}
		*dropUsers = append(*dropUsers, u.Name)
		if err := AddUser(ctx, cfg, u, NewPassword()); err != nil {
			t.Fatal(err)
		}
	}
	addUser(AppUser, p.Name+"_app", p.Name)
	addUser(AdminUser, p.Name+"_admin", p.Name)
	addUser(AppUser, p.Name+"_old", p.Name)
	addUser(AppUser, p.Name+"_future", p.Name)
	addUser(AppUser, v2.Name+"_app", v2.Name)

	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// t.Cleanup, not defer: deferred calls run before the cleanups below,
	// which still need this connection.
	t.Cleanup(func() { admin.Close(context.Background()) })
	mustExec(t, admin, "ALTER ROLE "+ident(p.Name+"_old")+" VALID UNTIL '2000-01-01'")
	mustExec(t, admin, "ALTER ROLE "+ident(p.Name+"_future")+" VALID UNTIL 'infinity'")
	// v2's app user may also connect to p, but belongs to the longer v2.
	mustExec(t, admin, "GRANT CONNECT ON DATABASE "+ident(p.Name)+" TO "+ident(v2.Name+"_app"))
	// Named like a v2 user, so it's listed under v2, though it can only
	// connect to p: CONNECT is up to each database's owner, so it mustn't
	// decide where a role goes, or an owner could move roles around.
	other := v2.Name + "_other"
	*dropUsers = append(*dropUsers, other)
	mustExec(t, admin, "CREATE ROLE "+ident(other)+" LOGIN")
	mustExec(t, admin, "GRANT CONNECT ON DATABASE "+ident(p.Name)+" TO "+ident(other))
	// v2's owner may connect to p too, but it's v2's owner, not a user of p.
	mustExec(t, admin, "GRANT CONNECT ON DATABASE "+ident(p.Name)+" TO "+ident(v2.Name))
	// Revoked before v2's cleanup, or the grant on p keeps v2's role from being dropped.
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "REVOKE CONNECT ON DATABASE "+ident(p.Name)+" FROM "+ident(v2.Name)); err != nil {
			t.Errorf("revoking CONNECT from %s: %v", v2.Name, err)
		}
	})
	// A NOINHERIT member of p's owner doesn't use the owner's privileges
	// directly, but can SET ROLE to it at any time, so it's an admin user. It
	// doesn't inherit the owner's CONNECT either, and has none of its own, so
	// it's listed with can't connect.
	ops := p.Name + "_ops"
	*dropUsers = append(*dropUsers, ops)
	mustExec(t, admin, "CREATE ROLE "+ident(ops)+" LOGIN NOINHERIT")
	mustExec(t, admin, "GRANT "+ident(p.Name)+" TO "+ident(ops))
	// A user with a power beyond the project.
	boss := p.Name + "_boss"
	*dropUsers = append(*dropUsers, boss)
	mustExec(t, admin, "CREATE ROLE "+ident(boss)+" LOGIN CREATEROLE")
	mustExec(t, admin, "GRANT CONNECT ON DATABASE "+ident(p.Name)+" TO "+ident(boss))
	// Privileged through membership: in a CREATEROLE role, and in the owner
	// of another database, which gives it that project too.
	deputy, cross := p.Name+"_deputy", p.Name+"_cross"
	*dropUsers = append(*dropUsers, deputy, cross)
	for _, stmt := range []string{
		"CREATE ROLE " + ident(deputy) + " LOGIN",
		"GRANT " + ident(boss) + " TO " + ident(deputy),
		"GRANT CONNECT ON DATABASE " + ident(p.Name) + " TO " + ident(deputy),
		"CREATE ROLE " + ident(cross) + " LOGIN",
		"GRANT " + ident(v2.Name) + " TO " + ident(cross),
		"GRANT CONNECT ON DATABASE " + ident(p.Name) + " TO " + ident(cross),
	} {
		mustExec(t, admin, stmt)
	}

	// p_rep is a longer project the admin can't act for. Its reader can also
	// connect to p, but belongs to p_rep, so it's not a user of p.
	rep, repOwner, repReader := p.Name+"_rep", p.Name+"_rep_owner", p.Name+"_rep_ro"
	*dropUsers = append(*dropUsers, repReader, repOwner)
	mustExec(t, admin, "CREATE ROLE "+ident(repOwner)+" NOLOGIN")
	mustExec(t, admin, "GRANT "+ident(repOwner)+" TO "+ident(cfg.User))
	mustExec(t, admin, "CREATE DATABASE "+ident(rep)+" OWNER "+ident(repOwner))
	mustExec(t, admin, "REVOKE "+ident(repOwner)+" FROM "+ident(cfg.User))
	mustExec(t, admin, "CREATE ROLE "+ident(repReader)+" LOGIN")
	mustExec(t, admin, "GRANT CONNECT ON DATABASE "+ident(p.Name)+" TO "+ident(repReader))
	t.Cleanup(func() {
		for _, stmt := range []string{
			"GRANT " + ident(repOwner) + " TO " + ident(cfg.User),
			"DROP DATABASE IF EXISTS " + ident(rep),
		} {
			if _, err := admin.Exec(context.Background(), stmt); err != nil {
				t.Errorf("%s: %v", stmt, err)
			}
		}
	})

	// p_x is owned by a role not named after it, and a role named exactly
	// p_x is a member of that owner. The owner is shown as the owner, not as
	// a user; p_x is an admin user.
	x, xOwner := p.Name+"_x", p.Name+"_x_owner"
	*dropUsers = append(*dropUsers, x, xOwner)
	mustExec(t, admin, "CREATE ROLE "+ident(xOwner)+" LOGIN")
	mustExec(t, admin, "GRANT "+ident(xOwner)+" TO "+ident(cfg.User))
	mustExec(t, admin, "CREATE DATABASE "+ident(x)+" OWNER "+ident(xOwner))
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+ident(x)); err != nil {
			t.Errorf("dropping %s: %v", x, err)
		}
	})
	mustExec(t, admin, "CREATE ROLE "+ident(x)+" LOGIN")
	mustExec(t, admin, "GRANT "+ident(xOwner)+" TO "+ident(x))

	// Named like users of p: one can't connect, so it's listed with a note;
	// one can't log in, so it's no user at all.
	for _, r := range []string{p.Name + "_noconnect LOGIN", p.Name + "_nologin NOLOGIN"} {
		name := strings.Fields(r)[0]
		*dropUsers = append(*dropUsers, name)
		mustExec(t, admin, "CREATE ROLE "+ident(name)+" "+strings.Fields(r)[1])
	}
	mustExec(t, admin, "GRANT CONNECT ON DATABASE "+ident(p.Name)+" TO "+ident(p.Name+"_nologin"))

	// A database whose owner the admin isn't a member of, set up as in
	// TestAddUserNeedsMembershipInOwner.
	foreign := "nellie_it_" + strings.ToLower(rand.Text()[:8])
	foreignOwner := foreign + "_owner"
	mustExec(t, admin, "CREATE ROLE "+ident(foreignOwner)+" NOLOGIN")
	mustExec(t, admin, "GRANT "+ident(foreignOwner)+" TO "+ident(cfg.User))
	mustExec(t, admin, "CREATE DATABASE "+ident(foreign)+" OWNER "+ident(foreignOwner))
	mustExec(t, admin, "REVOKE "+ident(foreignOwner)+" FROM "+ident(cfg.User))
	t.Cleanup(func() {
		for _, stmt := range []string{
			"GRANT " + ident(foreignOwner) + " TO " + ident(cfg.User),
			"DROP DATABASE IF EXISTS " + ident(foreign),
			"DROP ROLE IF EXISTS " + ident(foreignOwner),
		} {
			if _, err := admin.Exec(context.Background(), stmt); err != nil {
				t.Errorf("%s: %v", stmt, err)
			}
		}
	})

	// Databases the admin owns that its owner made a template, or closed to
	// connections. Both are still listed: an owner can switch either setting,
	// so leaving them out would let it hide its project. A template can't be
	// dropped, so the cleanup (and TestMain's sweep) turn IS_TEMPLATE off first.
	template := "nellie_it_" + strings.ToLower(rand.Text()[:8])
	closed := "nellie_it_" + strings.ToLower(rand.Text()[:8])
	mustExec(t, admin, "CREATE DATABASE "+ident(template))
	t.Cleanup(func() {
		for _, stmt := range []string{
			"ALTER DATABASE " + ident(template) + " IS_TEMPLATE false",
			"DROP DATABASE IF EXISTS " + ident(template),
		} {
			if _, err := admin.Exec(context.Background(), stmt); err != nil {
				t.Errorf("%s: %v", stmt, err)
			}
		}
	})
	mustExec(t, admin, "ALTER DATABASE "+ident(template)+" IS_TEMPLATE true")
	mustExec(t, admin, "CREATE DATABASE "+ident(closed)+" ALLOW_CONNECTIONS false")
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+ident(closed)); err != nil {
			t.Errorf("dropping %s: %v", closed, err)
		}
	})

	projects, err := ListProjects(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The server may hold other projects; only the test's matter.
	got := map[string]ProjectInfo{}
	for _, pr := range projects {
		got[pr.Name] = pr
	}
	// A superuser admin has every owner's privileges, so it may list foreign
	// and rep.
	var super bool
	if err := admin.QueryRow(ctx, "SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&super); err != nil {
		t.Fatal(err)
	}
	if !super {
		for _, db := range []string{foreign, rep} {
			if _, ok := got[db]; ok {
				t.Errorf("listed %s, whose owner the admin isn't a member of", db)
			}
		}
	}
	for _, db := range []string{template, closed} {
		if _, ok := got[db]; !ok {
			t.Errorf("%s is missing: its owner can't hide it with IS_TEMPLATE or ALLOW_CONNECTIONS", db)
		}
	}

	want := map[string]ProjectInfo{
		p.Name: {Name: p.Name, Owner: p.Name, Users: []UserInfo{
			{Name: p.Name + "_admin", Kind: AdminUser, CanConnect: true},
			{Name: p.Name + "_app", Kind: AppUser, CanConnect: true},
			{Name: p.Name + "_boss", Kind: AppUser, Powers: "CREATEROLE", CanConnect: true},
			{Name: p.Name + "_cross", Kind: AppUser, Powers: "member of " + v2.Name, CanConnect: true},
			{Name: p.Name + "_deputy", Kind: AppUser, Powers: "member of " + boss, CanConnect: true},
			{Name: p.Name + "_future", Kind: AppUser, CanConnect: true},
			{Name: p.Name + "_noconnect", Kind: AppUser},
			{Name: p.Name + "_old", Kind: AppUser, CanConnect: true, Expired: true},
			{Name: p.Name + "_ops", Kind: AdminUser},
		}},
		v2.Name: {Name: v2.Name, Owner: v2.Name, Users: []UserInfo{
			{Name: v2.Name + "_app", Kind: AppUser, CanConnect: true},
			{Name: v2.Name + "_other", Kind: AppUser},
		}},
		x: {Name: x, Owner: xOwner, Users: []UserInfo{
			{Name: x, Kind: AdminUser, CanConnect: true},
		}},
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("project %s missing from %+v", name, projects)
			continue
		}
		if g.Owner != w.Owner || !slices.Equal(g.Users, w.Users) {
			t.Errorf("project %s:\n got %+v\nwant %+v", name, g, w)
		}
	}
}

// Value: protects=a project owner can't hijack the admin's list query by shadowing a catalog function in the database the admin connects to; fails_when=the SET search_path in ListProjects is removed or moved after the query; why_new=TestListProjects connects to postgres, whose public schema no project role controls; seam=none
func TestListProjectsIgnoresShadowedFunctions(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	p, _, _ := newTestProject(t, cfg)

	// The project owner puts starts_with(name, text) in its public schema. It
	// matches r.rolname exactly, so it beats pg_catalog.starts_with(text, text)
	// on the default search_path, and it runs with the admin's privileges.
	inProject := cfg.Copy()
	inProject.Database = p.Name
	admin, err := pgx.ConnectConfig(ctx, inProject)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })
	mustExec(t, admin, "SET ROLE "+ident(p.Name))
	mustExec(t, admin, `CREATE FUNCTION public.starts_with(name, text) RETURNS boolean
		LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'shadowed starts_with ran'; END$$`)
	mustExec(t, admin, "RESET ROLE")

	// Control: without the guard, the query runs the owner's function.
	if _, err := admin.Exec(ctx, ListSQL); err == nil || !strings.Contains(err.Error(), "shadowed starts_with ran") {
		t.Fatalf("the shadowing function didn't run on a plain connection, so this test proves nothing: %v", err)
	}

	projects, err := ListProjects(ctx, inProject)
	if err != nil {
		t.Fatalf("ListProjects ran the project owner's function: %v", err)
	}
	if !slices.ContainsFunc(projects, func(pr ProjectInfo) bool { return pr.Name == p.Name }) {
		t.Errorf("project %s missing from %+v", p.Name, projects)
	}
}

// Value: protects=the role nellie connects as is never listed as a project user, even when its name fits a project (nellie_admin and a project nellie); fails_when=the current_user filter is dropped; why_new=new rule; seam=none
func TestListProjectsLeavesOutTheAdmin(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	p, _, dropUsers := newTestProject(t, cfg)

	// A second admin, named like a user of p, that has p's owner privileges.
	root := p.Name + "_root"
	password := NewPassword()
	verifier, err := scramVerifier(password)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })
	*dropUsers = append(*dropUsers, root)
	mustExec(t, admin, "CREATE ROLE "+ident(root)+" LOGIN PASSWORD "+literal(verifier))
	mustExec(t, admin, "GRANT "+ident(p.Name)+" TO "+ident(root))

	rootCfg := cfg.Copy()
	rootCfg.User, rootCfg.Password = root, password
	projects, err := ListProjects(ctx, rootCfg)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(projects, func(pr ProjectInfo) bool { return pr.Name == p.Name })
	if i < 0 {
		t.Fatalf("project %s missing from %+v", p.Name, projects)
	}
	if slices.ContainsFunc(projects[i].Users, func(u UserInfo) bool { return u.Name == root }) {
		t.Errorf("the admin %s is listed as a user of %s: %+v", root, p.Name, projects[i].Users)
	}
}

// Value: protects=superusers and members of predefined pg_* roles are listed as privileged, with what they have, not hidden or labeled application; fails_when=powers drops a case; why_new=new type; seam=none
func TestListProjectsFlagsPrivilegedRoles(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })
	var super bool
	if err := admin.QueryRow(ctx, "SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&super); err != nil {
		t.Fatal(err)
	}
	if !super {
		t.Skip("creating a superuser and granting pg_monitor need a superuser NELLIE_TEST_DSN")
	}

	p, _, dropUsers := newTestProject(t, cfg)
	su, mon := p.Name+"_su", p.Name+"_mon"
	*dropUsers = append(*dropUsers, su, mon)
	mustExec(t, admin, "CREATE ROLE "+ident(su)+" LOGIN SUPERUSER")
	mustExec(t, admin, "CREATE ROLE "+ident(mon)+" LOGIN")
	mustExec(t, admin, "GRANT pg_monitor TO "+ident(mon))
	mustExec(t, admin, "GRANT CONNECT ON DATABASE "+ident(p.Name)+" TO "+ident(mon))

	projects, err := ListProjects(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(projects, func(pr ProjectInfo) bool { return pr.Name == p.Name })
	if i < 0 {
		t.Fatalf("project %s missing from %+v", p.Name, projects)
	}
	powers := map[string]string{}
	for _, u := range projects[i].Users {
		powers[u.Name] = u.Powers
	}
	if got := powers[su]; got != "SUPERUSER" {
		t.Errorf("powers of superuser %s = %q, want SUPERUSER", su, got)
	}
	if got := powers[mon]; !strings.HasPrefix(got, "member of pg_monitor") {
		t.Errorf("powers of %s = %q, want membership in pg_monitor", mon, got)
	}
}

// Value: protects=nellie refuses a connection database whose owner made every session act as another role, rather than listing or rotating as that role; fails_when=pinSession stops checking; why_new=red team; seam=none
func TestPinSessionRefusesDatabaseRole(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	p, _, _ := newTestProject(t, cfg)

	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })
	// What p's owner can do to its own database.
	mustExec(t, admin, "ALTER DATABASE "+ident(p.Name)+" SET role = "+literal(p.Name))

	inProject := cfg.Copy()
	inProject.Database = p.Name
	if _, err := ListProjects(ctx, inProject); err == nil || !strings.Contains(err.Error(), "acts as role "+strconv.Quote(p.Name)) {
		t.Errorf("ListProjects: got %v, want a refusal naming role %s", err, p.Name)
	}
	if _, err := RotatePassword(ctx, inProject, p.Name, NewPassword()); err == nil || !strings.Contains(err.Error(), "acts as role") {
		t.Errorf("RotatePassword: got %v, want the same refusal", err)
	}
}

// Value: protects=the admin's own role setting still works in a database that also has one, and pg_database_owner membership isn't a power; fails_when=pinSession refuses any switch or checks the database's setting, or the pg_database_owner exception goes; why_new=only the refusal was tested; seam=none
func TestPinSessionAllowsAdminsOwnRole(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	p, _, dropUsers := newTestProject(t, cfg)
	u, err := NewUser(AdminUser, p.Name+"_admin", p.Name)
	if err != nil {
		t.Fatal(err)
	}
	*dropUsers = append(*dropUsers, u.Name)
	if err := AddUser(ctx, cfg, u, NewPassword()); err != nil {
		t.Fatal(err)
	}

	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })
	// The admin chose to act as p in p; p's owner also set a role there,
	// which the admin's own setting overrides.
	mustExec(t, admin, "ALTER ROLE "+ident(cfg.User)+" IN DATABASE "+ident(p.Name)+" SET role = "+literal(p.Name))
	mustExec(t, admin, "ALTER DATABASE "+ident(p.Name)+" SET role = "+literal(p.Name))

	inProject := cfg.Copy()
	inProject.Database = p.Name
	projects, err := ListProjects(ctx, inProject)
	if err != nil {
		t.Fatalf("ListProjects refused the admin's own role setting: %v", err)
	}
	// Connected to p, its admin user is a member of pg_database_owner, which
	// is no power beyond the project.
	i := slices.IndexFunc(projects, func(pr ProjectInfo) bool { return pr.Name == p.Name })
	if i < 0 || !slices.Equal(projects[i].Users, []UserInfo{{Name: u.Name, Kind: AdminUser, CanConnect: true}}) {
		t.Errorf("project %s: got %+v, want only %s as an unprivileged admin user", p.Name, projects, u.Name)
	}
}

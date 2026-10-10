//go:build integration

package pg

import (
	"context"
	"crypto/rand"
	"slices"
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
	// Named like a v2 user, but it can only connect to p, so it belongs to p.
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
	// directly, but can SET ROLE to it at any time, so it's an admin user.
	// It doesn't inherit the owner's CONNECT either, so that's granted.
	ops := p.Name + "_ops"
	*dropUsers = append(*dropUsers, ops)
	mustExec(t, admin, "CREATE ROLE "+ident(ops)+" LOGIN NOINHERIT")
	mustExec(t, admin, "GRANT "+ident(p.Name)+" TO "+ident(ops))
	mustExec(t, admin, "GRANT CONNECT ON DATABASE "+ident(p.Name)+" TO "+ident(ops))

	// Named like users of p, but one has no CONNECT and one can't log in.
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

	// Databases the admin owns but that aren't projects: a template, and one
	// nobody can connect to. A template can't be dropped, so the cleanup (and
	// TestMain's sweep) turn IS_TEMPLATE off first.
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
	for db, why := range map[string]string{
		foreign:  "whose owner the admin isn't a member of",
		template: "a template",
		closed:   "which allows no connections",
	} {
		if _, ok := got[db]; ok {
			t.Errorf("listed %s, %s", db, why)
		}
	}

	want := map[string]ProjectInfo{
		p.Name: {Name: p.Name, Owner: p.Name, Users: []UserInfo{
			{Name: p.Name + "_admin", Kind: AdminUser},
			{Name: p.Name + "_app", Kind: AppUser},
			{Name: p.Name + "_future", Kind: AppUser},
			{Name: p.Name + "_old", Kind: AppUser, Expired: true},
			{Name: p.Name + "_ops", Kind: AdminUser},
			{Name: v2.Name + "_other", Kind: AppUser},
		}},
		v2.Name: {Name: v2.Name, Owner: v2.Name, Users: []UserInfo{
			{Name: v2.Name + "_app", Kind: AppUser},
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

// Value: protects=superusers never appear as project users; fails_when=the rolsuper filter is dropped; why_new=new rule; seam=none
func TestListProjectsLeavesOutSuperusers(t *testing.T) {
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
		t.Skip("creating a superuser needs a superuser NELLIE_TEST_DSN")
	}

	p, _, dropUsers := newTestProject(t, cfg)
	su := p.Name + "_su"
	*dropUsers = append(*dropUsers, su)
	mustExec(t, admin, "CREATE ROLE "+ident(su)+" LOGIN SUPERUSER")

	projects, err := ListProjects(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, pr := range projects {
		if slices.ContainsFunc(pr.Users, func(u UserInfo) bool { return u.Name == su }) {
			t.Errorf("superuser %s is listed as a user of %s", su, pr.Name)
		}
	}
}

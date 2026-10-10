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

// Value: protects=nellie list shows exactly the projects the admin can act for and the right users under each: app and admin types, expired roles flagged, the longest matching project wins, and roles that can't connect, can't log in, or belong to databases the admin isn't a member of stay out; fails_when=the membership filter, the CONNECT check, the longest-prefix rule or the admin/app classification changes; why_new=new code; seam=none
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
	addUser(AppUser, v2.Name+"_app", v2.Name)

	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// t.Cleanup, not defer: deferred calls run before the cleanups below,
	// which still need this connection.
	t.Cleanup(func() { admin.Close(context.Background()) })
	mustExec(t, admin, "ALTER ROLE "+ident(p.Name+"_old")+" VALID UNTIL '2000-01-01'")
	// v2's app user may also connect to p, but belongs to the longer v2.
	mustExec(t, admin, "GRANT CONNECT ON DATABASE "+ident(p.Name)+" TO "+ident(v2.Name+"_app"))

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

	projects, err := ListProjects(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The server may hold other projects; only the test's matter.
	got := map[string]ProjectInfo{}
	for _, pr := range projects {
		got[pr.Name] = pr
	}
	if _, ok := got[foreign]; ok {
		t.Errorf("listed %s, whose owner the admin isn't a member of", foreign)
	}

	want := map[string]ProjectInfo{
		p.Name: {Name: p.Name, Owner: p.Name, Users: []UserInfo{
			{Name: p.Name + "_admin", Kind: AdminUser},
			{Name: p.Name + "_app", Kind: AppUser},
			{Name: p.Name + "_old", Kind: AppUser, Expired: true},
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

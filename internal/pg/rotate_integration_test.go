//go:build integration

package pg

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestRotatePassword(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	p, ownerPassword, dropUsers := newTestProject(t, cfg)

	u, err := NewUser(AppUser, p.Name+"_app", p.Name)
	if err != nil {
		t.Fatal(err)
	}
	*dropUsers = append(*dropUsers, u.Name)
	oldPassword := NewPassword()
	if err := AddUser(ctx, cfg, u, oldPassword); err != nil {
		t.Fatal(err)
	}
	// An admin user is a member of the owner, so it also checks that the
	// membership refusal in checkRotatable leaves nellie's own roles alone.
	a, err := NewUser(AdminUser, p.Name+"_admin", p.Name)
	if err != nil {
		t.Fatal(err)
	}
	*dropUsers = append(*dropUsers, a.Name)
	adminPassword := NewPassword()
	if err := AddUser(ctx, cfg, a, adminPassword); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct{ role, old string }{
		{u.Name, oldPassword},
		{a.Name, adminPassword},
		{p.Name, ownerPassword}, // the owner is rotated the same way
	} {
		t.Run(tt.role, func(t *testing.T) {
			newPassword := NewPassword()
			rot, err := RotatePassword(ctx, cfg, tt.role, newPassword)
			if err != nil {
				t.Fatal(err)
			}
			// Its own project is no power: an owner owns p, an admin user is a
			// member of p's owner.
			if rot.Database != p.Name || rot.Expired || rot.Powers != nil || rot.Template {
				t.Errorf("got %+v, want database %q, not expired, no powers", rot, p.Name)
			}
			connectAs(t, cfg, tt.role, newPassword, p.Name)

			c := cfg.Copy()
			c.User, c.Password, c.Database = tt.role, tt.old, p.Name
			if conn, err := pgx.ConnectConfig(ctx, c); err == nil {
				conn.Close(ctx)
				t.Error("the old password still works")
			}
		})
	}
}

func TestRotatePasswordRefuses(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// t.Cleanup, not defer: deferred calls run before the cleanups below,
	// which still need this connection to drop what the test created.
	t.Cleanup(func() { admin.Close(context.Background()) })

	// "nellie_it_" so TestMain's sweep drops it if the cleanup doesn't run.
	nologin := "nellie_it_nologin_" + strings.ToLower(NewPassword()[:8])
	mustExec(t, admin, "CREATE ROLE "+ident(nologin)+" NOLOGIN")
	t.Cleanup(func() { admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+ident(nologin)) })
	// Another admin: CREATEROLE is the one such power a CREATEROLE admin can
	// hand out itself (REPLICATION and BYPASSRLS need the admin to have them).
	otherAdmin := "nellie_it_admin_" + strings.ToLower(NewPassword()[:8])
	mustExec(t, admin, "CREATE ROLE "+ident(otherAdmin)+" LOGIN CREATEROLE")
	t.Cleanup(func() { admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+ident(otherAdmin)) })
	// A plain login role that can SET ROLE to that admin.
	viaAdmin := "nellie_it_via_" + strings.ToLower(NewPassword()[:8])
	mustExec(t, admin, "CREATE ROLE "+ident(viaAdmin)+" LOGIN IN ROLE "+ident(otherAdmin))
	t.Cleanup(func() { admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+ident(viaAdmin)) })

	tests := []struct {
		name, role, want string
	}{
		{"missing", "nellie_it_does_not_exist", "does not exist"},
		{"nologin", nologin, "can't log in"},
		{"admin itself", cfg.User, "admin role"},
		// Value: protects=nellie can't be used to take over another admin's login; fails_when=checkRotatable stops checking rolcreaterole; why_new=privileged non-superusers were rotatable; seam=none
		{"another admin", otherAdmin, "has CREATEROLE"},
		// Value: protects=a plain role that can SET ROLE to an admin is refused like the admin; fails_when=the membership clause is dropped; why_new=pass-2 security review; seam=none
		{"member of another admin", viaAdmin, "is a member of " + strconv.Quote(otherAdmin)},
	}

	// The test server's superuser, if it has a name nellie accepts.
	var super string
	err = admin.QueryRow(ctx, "SELECT rolname FROM pg_roles WHERE rolsuper AND rolname ~ '^[a-z][a-z0-9_]*$' AND rolname NOT LIKE 'pg\\_%' LIMIT 1").Scan(&super)
	if err == nil && super != cfg.User {
		tests = append(tests, struct{ name, role, want string }{"superuser", super, "superuser"})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RotatePassword(ctx, cfg, tt.role, NewPassword())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("got %v, want an error containing %q", err, tt.want)
			}
			if tt.name == "missing" && !errors.Is(err, ErrNotFound) {
				t.Errorf("got %v, want ErrNotFound", err)
			}
		})
	}
}

// Value: protects=rotating a role whose VALID UNTIL has passed is reported, since the new password won't work until it's cleared; fails_when=the expiry check is dropped and nellie reports plain success; why_new=new check; seam=none
func TestRotatePasswordReportsExpiry(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) }) // see TestRotatePasswordRefuses

	p, _, dropUsers := newTestProject(t, cfg) // rotate-password only takes project roles
	role := p.Name + "_expired"
	*dropUsers = append(*dropUsers, role)
	mustExec(t, admin, "CREATE ROLE "+ident(role)+" LOGIN VALID UNTIL '2000-01-01'")

	rot, err := RotatePassword(ctx, cfg, role, NewPassword())
	if err != nil {
		t.Fatal(err)
	}
	if !rot.Expired {
		t.Error("Expired = false for a role whose VALID UNTIL is in 2000")
	}

	mustExec(t, admin, "ALTER ROLE "+ident(role)+" VALID UNTIL 'infinity'")
	if rot, err = RotatePassword(ctx, cfg, role, NewPassword()); err != nil || rot.Expired {
		t.Errorf("after VALID UNTIL 'infinity': got %+v, %v; want not expired", rot, err)
	}
}

// Value: protects=the URL names only the role's home by name, an admin's project owned by the role named after it, that the role can connect to; fails_when=projectHome drops one of those checks; why_new=red team: redirects; seam=none
func TestRotatePasswordPicksProjectByName(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	p, _, dropUsers := newTestProject(t, cfg)
	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })

	// A second project whose name is p's name plus "_v2"...
	other, err := NewProject(p.Name + "_v2")
	if err != nil {
		t.Fatal(err)
	}
	if err := CreateProject(ctx, cfg, other, NewPassword()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := dropProject(context.Background(), cfg, other, true); err != nil {
			t.Errorf("dropping %s: %v", other.Name, err)
		}
	})
	rotate := func(user string) string {
		t.Helper()
		rot, err := RotatePassword(ctx, cfg, user, NewPassword())
		if err != nil {
			t.Fatal(err)
		}
		return rot.Database
	}

	// ...and a user of p whose suffix starts with "v2_", from before nellie
	// refused such names (AddUser would now). By name it belongs to p_v2,
	// which it can't connect to: no URL rather than one for p. Granting it
	// CONNECT on p_v2 is what p_v2's owner could do; the URL then names p_v2,
	// the user's home, never p.
	ambiguous := p.Name + "_v2_app"
	*dropUsers = append(*dropUsers, ambiguous)
	mustExec(t, admin, "CREATE ROLE "+ident(ambiguous)+" LOGIN")
	mustExec(t, admin, "GRANT CONNECT ON DATABASE "+ident(p.Name)+" TO "+ident(ambiguous))
	if db := rotate(ambiguous); db != "" {
		t.Errorf("database = %q, want none: the name picks %s, which the user can't connect to", db, other.Name)
	}

	u, err := NewUser(AppUser, p.Name+"_app", p.Name)
	if err != nil {
		t.Fatal(err)
	}
	*dropUsers = append(*dropUsers, u.Name)
	if err := AddUser(ctx, cfg, u, NewPassword()); err != nil {
		t.Fatal(err)
	}
	if db := rotate(u.Name); db != p.Name {
		t.Fatalf("database = %q, want %s", db, p.Name)
	}

	// p closed to connections: no URL, it couldn't be used.
	mustExec(t, admin, "ALTER DATABASE "+ident(p.Name)+" ALLOW_CONNECTIONS false")
	if db := rotate(u.Name); db != "" {
		t.Errorf("database = %q, want none: %s allows no connections", db, p.Name)
	}
	mustExec(t, admin, "ALTER DATABASE "+ident(p.Name)+" ALLOW_CONNECTIONS true")

	// A database named like the user, which PUBLIC can connect to, created by
	// a role with CREATEDB: here p's owner, which the admin acts for. The
	// name now picks it, but its owner isn't named after it, so no URL.
	mustExec(t, admin, "CREATE DATABASE "+ident(u.Name)+" OWNER "+ident(p.Name))
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+ident(u.Name)); err != nil {
			t.Errorf("dropping %s: %v", u.Name, err)
		}
	})
	// Value: protects=a look-alike database a project owner created doesn't make an outside role rotatable; fails_when=rotatableProject drops the owner-named-after-it rule; why_new=Fable review #1; seam=none
	if _, err := RotatePassword(ctx, cfg, u.Name, NewPassword()); err == nil || !strings.Contains(err.Error(), "isn't in any project") {
		t.Errorf("rotating %s: got %v, want a refusal: its home %s isn't owned by a role named after it", u.Name, err, u.Name)
	}

	// Value: protects=no URL names a database the admin can't act for, though its owner is named after it and the user can connect; fails_when=projectHome drops its pg_has_role(datdba, 'USAGE') check; why_new=every URL case used the admin's own projects; seam=none; no_claim=skipped for a superuser admin, which acts for every owner
	t.Run("database the admin can't act for", func(t *testing.T) {
		var super bool
		if err := admin.QueryRow(ctx, "SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&super); err != nil {
			t.Fatal(err)
		}
		if super {
			t.Skip("a superuser admin acts for every database's owner")
		}
		// Shaped like a nellie project (owner named after it, PUBLIC keeps
		// CONNECT), but the admin gives up its membership in the owner.
		q := "nellie_it_" + strings.ToLower(NewPassword()[:8])
		qApp := q + "_app"
		*dropUsers = append(*dropUsers, qApp, q)
		mustExec(t, admin, "CREATE ROLE "+ident(q)+" NOLOGIN")
		mustExec(t, admin, "GRANT "+ident(q)+" TO "+ident(cfg.User))
		mustExec(t, admin, "CREATE DATABASE "+ident(q)+" OWNER "+ident(q))
		t.Cleanup(func() {
			for _, stmt := range []string{
				"GRANT " + ident(q) + " TO " + ident(cfg.User),
				"DROP DATABASE IF EXISTS " + ident(q),
			} {
				if _, err := admin.Exec(context.Background(), stmt); err != nil {
					t.Errorf("%s: %v", stmt, err)
				}
			}
		})
		mustExec(t, admin, "REVOKE "+ident(q)+" FROM "+ident(cfg.User))
		mustExec(t, admin, "CREATE ROLE "+ident(qApp)+" LOGIN")
		// Not a project of the admin's, so nellie list doesn't show q_app,
		// and rotate-password won't touch it.
		if _, err := RotatePassword(ctx, cfg, qApp, NewPassword()); err == nil || !strings.Contains(err.Error(), "isn't in any project") {
			t.Errorf("rotating %s: got %v, want a refusal: the admin can't act for %s's owner", qApp, err, q)
		}
		// Control: with the membership back, the same database gets the URL,
		// so membership is what made the difference above.
		mustExec(t, admin, "GRANT "+ident(q)+" TO "+ident(cfg.User))
		if db := rotate(qApp); db != q {
			t.Errorf("control: database = %q, want %s once the admin acts for its owner", db, q)
		}
	})
}

// Value: protects=add-project and add-user refuse names that would make the name-to-project mapping ambiguous; fails_when=either check is dropped; why_new=JSC-3; seam=none
func TestNamesMustBeUnambiguous(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	p, _, dropUsers := newTestProject(t, cfg)

	app, err := NewUser(AppUser, p.Name+"_v2_app", p.Name)
	if err != nil {
		t.Fatal(err)
	}
	*dropUsers = append(*dropUsers, app.Name)
	if err := AddUser(ctx, cfg, app, NewPassword()); err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })
	// Another login role a project p_v2 would claim, named with a control
	// character: the refusal must quote it, not send it to the terminal.
	bell := p.Name + "_v2_\a"
	*dropUsers = append(*dropUsers, bell)
	mustExec(t, admin, "CREATE ROLE "+ident(bell)+" LOGIN")

	// A project p_v2 would claim p's user p_v2_app.
	v2, err := NewProject(p.Name + "_v2")
	if err != nil {
		t.Fatal(err)
	}
	err = CreateProject(ctx, cfg, v2, NewPassword())
	if !errors.Is(err, ErrAmbiguous) || !strings.Contains(err.Error(), strconv.Quote(app.Name)) ||
		!strings.Contains(err.Error(), strconv.Quote(bell)) || strings.Contains(err.Error(), "\a") {
		t.Errorf("CreateProject(%s) = %v, want ErrAmbiguous naming %s and %q, escaped", v2.Name, err, app.Name, bell)
		if err == nil {
			dropProject(context.Background(), cfg, v2, true)
		}
	}

	// The other order: with a database p_x, a user p_x_app of p would belong to it.
	x := p.Name + "_x"
	mustExec(t, admin, "CREATE DATABASE "+ident(x))
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+ident(x)); err != nil {
			t.Errorf("dropping %s: %v", x, err)
		}
	})
	xApp, err := NewUser(AppUser, x+"_app", p.Name)
	if err != nil {
		t.Fatal(err)
	}
	*dropUsers = append(*dropUsers, xApp.Name)
	if err := AddUser(ctx, cfg, xApp, NewPassword()); !errors.Is(err, ErrAmbiguous) || !strings.Contains(err.Error(), "database "+strconv.Quote(x)) {
		t.Errorf("AddUser(%s) = %v, want ErrAmbiguous naming database %s", xApp.Name, err, x)
	}

	// Value: protects=add-project refuses only names that would move a login role: not for databases, NOLOGIN roles, or roles a longer database already claims; fails_when=the guard goes back to plain prefix matching or counts NOLOGIN roles; why_new=red team: order dependence and NOLOGIN groups; seam=none
	t.Run("only moving a login role refuses a name", func(t *testing.T) {
		q, err := NewProject("nellie_it_" + strings.ToLower(NewPassword()[:8]))
		if err != nil {
			t.Fatal(err)
		}
		// q_v2 first, with its user q_v2_app, which stays q_v2's when q
		// exists; a database q_db and a NOLOGIN role q_grp move nobody.
		qv2, err := NewProject(q.Name + "_v2")
		if err != nil {
			t.Fatal(err)
		}
		if err := CreateProject(ctx, cfg, qv2, NewPassword()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := dropProject(context.Background(), cfg, qv2, true); err != nil {
				t.Errorf("dropping %s: %v", qv2.Name, err)
			}
		})
		qApp, err := NewUser(AppUser, qv2.Name+"_app", qv2.Name)
		if err != nil {
			t.Fatal(err)
		}
		*dropUsers = append(*dropUsers, qApp.Name, q.Name+"_grp")
		if err := AddUser(ctx, cfg, qApp, NewPassword()); err != nil {
			t.Fatal(err)
		}
		qDB := q.Name + "_db"
		mustExec(t, admin, "CREATE DATABASE "+ident(qDB))
		t.Cleanup(func() {
			if _, err := admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+ident(qDB)); err != nil {
				t.Errorf("dropping %s: %v", qDB, err)
			}
		})
		mustExec(t, admin, "CREATE ROLE "+ident(q.Name+"_grp")+" NOLOGIN")

		if err := CreateProject(ctx, cfg, q, NewPassword()); err != nil {
			t.Fatalf("CreateProject(%s) = %v, want it allowed: nothing would move", q.Name, err)
		}
		t.Cleanup(func() {
			if err := dropProject(context.Background(), cfg, q, true); err != nil {
				t.Errorf("dropping %s: %v", q.Name, err)
			}
		})
	})

	// Value: protects=add-project and add-user don't run functions a project owner planted in the admin's connection database; fails_when=pinSession is dropped from add-*; why_new=only list's query was tested against shadowing; seam=none; no_claim=only starts_with(name, text) and length(name) are planted
	t.Run("planted functions in the connection database", func(t *testing.T) {
		// As in TestListProjectsIgnoresShadowedFunctions: exact matches for
		// name arguments beat pg_catalog's text versions on the default
		// search_path, which pinSession pins for add-* too.
		inProject := cfg.Copy()
		inProject.Database = p.Name
		owner, err := pgx.ConnectConfig(ctx, inProject)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { owner.Close(context.Background()) })
		mustExec(t, owner, "SET ROLE "+ident(p.Name))
		mustExec(t, owner, `CREATE FUNCTION public.starts_with(name, text) RETURNS boolean
			LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'planted starts_with ran'; END$$`)
		mustExec(t, owner, `CREATE FUNCTION public.length(name) RETURNS integer
			LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'planted length ran'; END$$`)
		mustExec(t, owner, "RESET ROLE")
		// Control: unqualified calls do run them, so the checks below mean something.
		for _, sql := range []string{
			"SELECT starts_with(datname, 'x') FROM pg_database",
			"SELECT length(datname) FROM pg_database",
		} {
			if _, err := owner.Exec(ctx, sql); err == nil || !strings.Contains(err.Error(), "planted") {
				t.Fatalf("%s didn't run the planted function, so this test proves nothing: %v", sql, err)
			}
		}

		q, err := NewProject("nellie_it_" + strings.ToLower(NewPassword()[:8]))
		if err != nil {
			t.Fatal(err)
		}
		if err := CreateProject(ctx, inProject, q, NewPassword()); err != nil {
			t.Errorf("CreateProject from %s: %v", p.Name, err)
		} else {
			t.Cleanup(func() {
				if err := dropProject(context.Background(), cfg, q, true); err != nil {
					t.Errorf("dropping %s: %v", q.Name, err)
				}
			})
		}
		u, err := NewUser(AppUser, p.Name+"_planted", p.Name)
		if err != nil {
			t.Fatal(err)
		}
		*dropUsers = append(*dropUsers, u.Name)
		if err := AddUser(ctx, inProject, u, NewPassword()); err != nil {
			t.Errorf("AddUser from %s: %v", p.Name, err)
		}
		if _, err := RotatePassword(ctx, inProject, u.Name, NewPassword()); err != nil {
			t.Errorf("RotatePassword from %s: %v", p.Name, err)
		}
	})
}

// Value: protects=rotate-password reports powers the new password carries beyond the project, as list shows them; fails_when=rolePowers stops being called or loses a power; why_new=red team: list and rotate disagreed; seam=none
func TestRotatePasswordReportsPowers(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	p, _, dropUsers := newTestProject(t, cfg)
	u, err := NewUser(AppUser, p.Name+"_app", p.Name)
	if err != nil {
		t.Fatal(err)
	}
	*dropUsers = append(*dropUsers, u.Name)
	if err := AddUser(ctx, cfg, u, NewPassword()); err != nil {
		t.Fatal(err)
	}
	rot, err := RotatePassword(ctx, cfg, u.Name, NewPassword())
	if err != nil {
		t.Fatal(err)
	}
	if rot.Powers != nil {
		t.Errorf("powers of a plain app user = %q, want none", rot.Powers)
	}

	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })
	mustExec(t, admin, "ALTER ROLE "+ident(u.Name)+" CREATEDB")
	rot, err = RotatePassword(ctx, cfg, u.Name, NewPassword())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rot.Powers, []string{"CREATEDB"}) {
		t.Errorf("powers = %q, want CREATEDB", rot.Powers)
	}

	var super bool
	if err := admin.QueryRow(ctx, "SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&super); err != nil {
		t.Fatal(err)
	}
	// A user owning another database, which the admin can't act for: list
	// shows "owner of" it, and so does rotate.
	spare := p.Name + "_spare"
	mustExec(t, admin, "ALTER ROLE "+ident(u.Name)+" NOCREATEDB")
	mustExec(t, admin, "GRANT "+ident(u.Name)+" TO "+ident(cfg.User))
	mustExec(t, admin, "CREATE DATABASE "+ident(spare)+" OWNER "+ident(u.Name))
	mustExec(t, admin, "REVOKE "+ident(u.Name)+" FROM "+ident(cfg.User))
	t.Cleanup(func() {
		// Dropping a database takes membership in its owner.
		admin.Exec(context.Background(), "GRANT "+ident(u.Name)+" TO "+ident(cfg.User))
		if _, err := admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+ident(spare)); err != nil {
			t.Errorf("dropping %s: %v", spare, err)
		}
	})
	rot, err = RotatePassword(ctx, cfg, u.Name, NewPassword())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rot.Powers, []string{"owner of " + spare}) {
		t.Errorf("powers of %s = %q, want [owner of %s] as list shows them", u.Name, rot.Powers, spare)
	}
	if super {
		return // a superuser admin acts for every database, so the next case is a project
	}

	// Value: protects=a role whose home by name is a database the admin can't act for isn't rotated, though list shows it under p with "belongs to"; fails_when=rotatableProject goes back to the longest matching project; why_new=Fable review #1; seam=none
	own := p.Name + "_own"
	*dropUsers = append(*dropUsers, own)
	mustExec(t, admin, "CREATE ROLE "+ident(own)+" LOGIN")
	mustExec(t, admin, "GRANT "+ident(own)+" TO "+ident(cfg.User))
	mustExec(t, admin, "CREATE DATABASE "+ident(own)+" OWNER "+ident(own))
	mustExec(t, admin, "REVOKE "+ident(own)+" FROM "+ident(cfg.User))
	t.Cleanup(func() {
		admin.Exec(context.Background(), "GRANT "+ident(own)+" TO "+ident(cfg.User))
		if _, err := admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+ident(own)); err != nil {
			t.Errorf("dropping %s: %v", own, err)
		}
	})
	if _, err := RotatePassword(ctx, cfg, own, NewPassword()); err == nil || !strings.Contains(err.Error(), "isn't in any project") {
		t.Errorf("rotating %s: got %v, want a refusal: it belongs to %s, not to p", own, err, own)
	}
}

// Value: protects=the owner of a project not named after its database can be rotated, as list shows it as the owner; fails_when=rotatableProject loses its owner half; why_new=Fable review #2: a regression from 0.2.0 for databases nellie didn't create; seam=none
func TestRotatePasswordAcceptsForeignNamedOwner(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })

	suffix := strings.ToLower(NewPassword()[:8])
	db, owner := "nellie_it_legacy_"+suffix, "nellie_it_deploy_"+suffix
	mustExec(t, admin, "CREATE ROLE "+ident(owner)+" LOGIN")
	mustExec(t, admin, "GRANT "+ident(owner)+" TO "+ident(cfg.User))
	mustExec(t, admin, "CREATE DATABASE "+ident(db)+" OWNER "+ident(owner))
	t.Cleanup(func() {
		for _, stmt := range []string{"DROP DATABASE IF EXISTS " + ident(db), "DROP ROLE IF EXISTS " + ident(owner)} {
			if _, err := admin.Exec(context.Background(), stmt); err != nil {
				t.Errorf("%s: %v", stmt, err)
			}
		}
	})

	rot, err := RotatePassword(ctx, cfg, owner, NewPassword())
	if err != nil {
		t.Fatalf("rotating %s, the owner of project %s: %v", owner, db, err)
	}
	if rot.Database != "" {
		t.Errorf("database = %q, want no URL: %s isn't named after %s", rot.Database, owner, db)
	}
}

// Value: protects=two add-* runs can't both pass the name checks before either creates; fails_when=lockAdd is dropped from CreateProject or AddUser; why_new=Fable review #9; seam=none
func TestAddWaitsForAnotherRun(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	holder, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { holder.Close(context.Background()) })
	if err := lockAdd(ctx, holder); err != nil {
		t.Fatal(err)
	}

	p, err := NewProject("nellie_it_" + strings.ToLower(NewPassword()[:8]))
	if err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	if err := CreateProject(short, cfg, p, NewPassword()); err == nil || !strings.Contains(err.Error(), "waiting for another nellie run") {
		t.Errorf("CreateProject while another run holds the lock: got %v, want it to wait and time out", err)
		if err == nil {
			dropProject(context.Background(), cfg, p, true)
		}
	}
}

// Value: protects=a role in a predefined pg_* role (here pg_monitor) is refused, since those grant powers nellie never hands out; fails_when=the pg_* membership clause is dropped or turned back into a short list; why_new=pass-3 red team; seam=none
func TestRotatePasswordRefusesPredefinedRoleMembers(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) }) // see TestRotatePasswordRefuses

	role := "nellie_it_monitor_" + strings.ToLower(NewPassword()[:8])
	mustExec(t, admin, "CREATE ROLE "+ident(role)+" LOGIN")
	t.Cleanup(func() { admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+ident(role)) })
	// Granting a predefined role needs ADMIN OPTION on it, which the usual
	// non-superuser test admin doesn't have.
	if _, err := admin.Exec(ctx, "GRANT pg_monitor TO "+ident(role)); err != nil {
		t.Skipf("the test admin can't grant pg_monitor (%v); run with a superuser DSN to cover this", err)
	}

	_, err = RotatePassword(ctx, cfg, role, NewPassword())
	if err == nil || !strings.Contains(err.Error(), "is a member of \"pg_monitor\"") {
		t.Errorf("got %v, want a refusal naming pg_monitor", err)
	}
}

// Value: protects=the add-project guard ignores the admin's own role, so an admin nellie_admin can still create a project nellie; fails_when=the rolname NOT IN (current_user, session_user) exclusion goes; why_new=run 4 review: the guard refused add-project for the admin's own prefix; seam=none
func TestProjectNameIgnoresTheAdmin(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })

	// A second admin-like login role q_adm, which the guard should skip
	// while it's the one connected, and count when it isn't.
	q := "nellie_it_" + strings.ToLower(NewPassword()[:8])
	role, password := q+"_adm", NewPassword()
	verifier, err := scramVerifier(password)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, admin, "CREATE ROLE "+ident(role)+" LOGIN PASSWORD "+literal(verifier))
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+ident(role)); err != nil {
			t.Errorf("dropping %s: %v", role, err)
		}
	})

	asRole := cfg.Copy()
	asRole.User, asRole.Password = role, password
	conn, err := pgx.ConnectConfig(ctx, asRole)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	if err := pinSession(ctx, conn); err != nil {
		t.Fatal(err)
	}
	if err := checkProjectNameUnambiguous(ctx, conn, q); err != nil {
		t.Errorf("as %s, project %s: %v, want it allowed: the admin itself never moves", role, q, err)
	}
	if err := pinSession(ctx, admin); err != nil {
		t.Fatal(err)
	}
	if err := checkProjectNameUnambiguous(ctx, admin, q); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("as %s, project %s: %v, want ErrAmbiguous for %s", cfg.User, q, err, role)
	}
}

// Value: protects=rotate-password only changes roles nellie list shows, never another service's role, which a CREATEROLE admin on Postgres 15 could otherwise rotate; fails_when=the shownProject check before ALTER ROLE goes; why_new=adversarial review; seam=none
func TestRotatePasswordRefusesRolesOutsideProjects(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })

	role := "nellie_it_stranger_" + strings.ToLower(NewPassword()[:8])
	mustExec(t, admin, "CREATE ROLE "+ident(role)+" LOGIN PASSWORD NULL")
	t.Cleanup(func() { admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+ident(role)) })

	refused := NewPassword()
	_, err = RotatePassword(ctx, cfg, role, refused)
	if err == nil || !strings.Contains(err.Error(), "isn't in any project") {
		t.Fatalf("got %v, want a refusal for a role outside every project", err)
	}
	// pg_authid isn't readable without superuser, so log in with the
	// refused password instead: it must not work.
	asRole := cfg.Copy()
	asRole.User, asRole.Password = role, refused
	if conn, err := pgx.ConnectConfig(ctx, asRole); err == nil {
		conn.Close(ctx)
		t.Errorf("role %s logs in with the refused password", role)
	}
}

// Value: protects=an admin that's a member of the owner without inheriting its privileges gets told why add-user can't grant, instead of "isn't a member"; fails_when=projectOwner stops telling MEMBER from USAGE; why_new=Codex: per-grant INHERIT on Postgres 16+ made a role-level NOINHERIT check wrong; seam=none
func TestAddUserExplainsMissingInherit(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	p, _, dropUsers := newTestProject(t, cfg)
	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })

	// A second admin, NOINHERIT, so its membership in p's owner (granted
	// with the role's default) doesn't carry the owner's privileges.
	role, password := p.Name+"_noinh", NewPassword()
	verifier, err := scramVerifier(password)
	if err != nil {
		t.Fatal(err)
	}
	*dropUsers = append(*dropUsers, role, p.Name+"_x")
	mustExec(t, admin, "CREATE ROLE "+ident(role)+" LOGIN NOINHERIT CREATEROLE PASSWORD "+literal(verifier))
	mustExec(t, admin, "GRANT "+ident(p.Name)+" TO "+ident(role))

	asRole := cfg.Copy()
	asRole.User, asRole.Password = role, password
	u, err := NewUser(AppUser, p.Name+"_x", p.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddUser(ctx, asRole, u, NewPassword()); err == nil || !strings.Contains(err.Error(), "doesn't inherit its privileges") {
		t.Errorf("AddUser as a NOINHERIT member of the owner: got %v, want the inherit explanation", err)
	}
}

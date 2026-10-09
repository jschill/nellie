//go:build integration

package pg

import (
	"context"
	"errors"
	"strings"
	"testing"

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
			if rot.Database != p.Name || rot.Expired {
				t.Errorf("got %+v, want database %q and not expired", rot, p.Name)
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
		{"member of another admin", viaAdmin, "is a member of " + otherAdmin},
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

// Value: protects=rotating a role whose VALID UNTIL has passed is reported, since the new password still can't log in; fails_when=the expiry check is dropped and nellie reports plain success for a locked-out role; why_new=new check; seam=none
func TestRotatePasswordReportsExpiry(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) }) // see TestRotatePasswordRefuses

	role := "nellie_it_expired_" + strings.ToLower(NewPassword()[:8])
	mustExec(t, admin, "CREATE ROLE "+ident(role)+" LOGIN VALID UNTIL '2000-01-01'")
	t.Cleanup(func() { admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+ident(role)) })

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

// Value: protects=the URL names the database the user can connect to when project names share a prefix; fails_when=projectDatabase picks the longest existing name without checking CONNECT; why_new=pass-2 red team: shop_v2_app of project shop was sent to project shop_v2; seam=none
func TestRotatePasswordPicksConnectableProject(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)
	p, _, dropUsers := newTestProject(t, cfg)

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
	// ...and a user of p whose suffix starts with "v2_".
	u, err := NewUser(AppUser, p.Name+"_v2_app", p.Name)
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
	if rot.Database != p.Name {
		t.Errorf("database = %q, want %q: the user can't connect to %s", rot.Database, p.Name, other.Name)
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
	if err == nil || !strings.Contains(err.Error(), "is a member of pg_monitor") {
		t.Errorf("got %v, want a refusal naming pg_monitor", err)
	}
}

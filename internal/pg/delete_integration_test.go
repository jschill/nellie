//go:build integration

package pg

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Value: protects=deletion waits for the shared lock and holds it through confirmation;
// fails_when=deletion omits the creation lock or releases it before confirmation;
// why_new=the existing lock test invokes CreateProject only;
// seam=none; no_claim=external tools honoring nellie's advisory lock.
func TestDeleteProjectSharesCreationLock(t *testing.T) {
	cfg := adminConfig(t)
	ctx := context.Background()
	p, _, _ := newTestProject(t, cfg)
	holder, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close(ctx)
	if err := lockAdd(ctx, holder); err != nil {
		t.Fatal(err)
	}
	waiting, cancel := context.WithCancel(ctx)
	defer cancel()
	waited, confirmed := false, false
	LockWait = func() { waited = true; cancel() }
	t.Cleanup(func() { LockWait = nil })
	err = DeleteProject(waiting, cfg, p.Name, false, func(Deletion) error {
		confirmed = true
		return context.Canceled
	})
	if !waited || confirmed || !errors.Is(err, context.Canceled) {
		t.Fatalf("waited=%t confirmed=%t error=%v", waited, confirmed, err)
	}
	mustExec(t, holder, "SELECT pg_advisory_unlock_all()")
	LockWait = nil
	acquired := true
	err = DeleteProject(ctx, cfg, p.Name, false, func(Deletion) error {
		confirmed = true
		if err := holder.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", int64(lockAddKey)).Scan(&acquired); err != nil {
			return err
		}
		return context.Canceled
	})
	if !confirmed || acquired || !errors.Is(err, context.Canceled) {
		t.Fatalf("confirmed=%t competing lock acquired=%t error=%v", confirmed, acquired, err)
	}
	var databaseExists, ownerExists bool
	if err := holder.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1),
 EXISTS(SELECT FROM pg_roles WHERE rolname=$1)`, p.Name).Scan(&databaseExists, &ownerExists); err != nil {
		t.Fatal(err)
	}
	if !databaseExists || !ownerExists {
		t.Fatalf("cancelled deletion changed database=%t owner=%t", databaseExists, ownerExists)
	}
}

func TestDeleteProjectRefusesUnsafeCaller(t *testing.T) {
	cfg := adminConfig(t)
	ctx := context.Background()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(ctx) })
	var version int
	if err := conn.QueryRow(ctx, "SELECT current_setting('server_version_num')::int").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version < 160000 {
		t.Skip("per-membership INHERIT requires PostgreSQL 16+")
	}
	for _, tc := range []struct {
		name, suffix, inherit, want string
	}{
		// Value: protects=matching project ownership without inherited privileges cannot authorize deletion;
		// fails_when=owner-name matching replaces the inherited-project privilege check;
		// why_new=existing foreign-owner tests change the owner name rather than membership inheritance;
		// seam=none; no_claim=PostgreSQL 15 global NOINHERIT semantics.
		{"owner not inherited", "x", "FALSE", "whose privileges the admin inherits"},
		// Value: protects=a selected caller role is never deleted even when it inherits project ownership;
		// fails_when=the current/session admin exclusion is removed from deletion planning;
		// why_new=existing fixture admins have names outside the selected project prefix;
		// seam=none; no_claim=every SET ROLE session configuration.
		{"admin selected", "_admin", "TRUE", "refusing to delete admin role"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, users := newTestProject(t, cfg)
			admin := p.Name + tc.suffix
			*users = append(*users, admin)
			password := NewPassword()
			mustExec(t, conn, "CREATE ROLE "+ident(admin)+" LOGIN CREATEROLE PASSWORD "+literal(password))
			mustExec(t, conn, "GRANT "+ident(p.Name)+" TO "+ident(admin)+" WITH ADMIN TRUE, INHERIT "+tc.inherit+", SET TRUE")
			var inherits bool
			if err := conn.QueryRow(ctx, "SELECT pg_has_role($1::name,$2::name,'USAGE')", admin, p.Name).Scan(&inherits); err != nil {
				t.Fatal(err)
			}
			if inherits != (tc.inherit == "TRUE") {
				t.Fatalf("fixture inheritance=%t, want %s", inherits, tc.inherit)
			}
			caller := cfg.Copy()
			caller.User, caller.Password = admin, password
			confirmed := false
			err := DeleteProject(ctx, caller, p.Name, false, func(Deletion) error {
				confirmed = true
				return nil
			})
			var databaseExists, ownerExists, adminExists bool
			if e := conn.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1),
 EXISTS(SELECT FROM pg_roles WHERE rolname=$1), EXISTS(SELECT FROM pg_roles WHERE rolname=$2)`, p.Name, admin).Scan(&databaseExists, &ownerExists, &adminExists); e != nil {
				t.Fatal(e)
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) || confirmed || !databaseExists || !ownerExists || !adminExists {
				t.Fatalf("error=%v confirmed=%t database=%t owner=%t admin=%t", err, confirmed, databaseExists, ownerExists, adminExists)
			}
		})
	}
}

// Value: protects=deletion refuses a project role the admin cannot drop before confirmation;
// fails_when=the PostgreSQL 16+ ADMIN OPTION guard is omitted;
// why_new=existing safety fixtures grant the admin drop permission for every selected role;
// seam=none; no_claim=PostgreSQL 15 CREATEROLE semantics.
func TestDeleteProjectRequiresRoleAdminOption(t *testing.T) {
	cfg := adminConfig(t)
	ctx := context.Background()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(ctx) })
	var super bool
	var version int
	if err = conn.QueryRow(ctx, "SELECT rolsuper,current_setting('server_version_num')::int FROM pg_roles WHERE rolname=current_user").Scan(&super, &version); err != nil {
		t.Fatal(err)
	}
	if super || version < 160000 {
		t.Skip("requires a non-superuser admin on PostgreSQL 16+")
	}
	p, _, users := newTestProject(t, cfg)
	user := p.Name + "_extra"
	admin := p.Name + "x"
	*users = append(*users, user, admin)
	mustExec(t, conn, "CREATE ROLE "+ident(user)+" LOGIN")
	password := NewPassword()
	mustExec(t, conn, "CREATE ROLE "+ident(admin)+" LOGIN CREATEROLE PASSWORD "+literal(password))
	mustExec(t, conn, "GRANT "+ident(p.Name)+" TO "+ident(admin)+" WITH ADMIN OPTION")
	restricted := cfg.Copy()
	restricted.User, restricted.Password = admin, password
	confirmed := false
	err = DeleteProject(ctx, restricted, p.Name, false, func(Deletion) error {
		confirmed = true
		return nil
	})
	var databaseExists, roleExists bool
	if e := conn.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1), EXISTS(SELECT FROM pg_roles WHERE rolname=$2)`, p.Name, user).Scan(&databaseExists, &roleExists); e != nil {
		t.Fatal(e)
	}
	if err == nil || !strings.Contains(err.Error(), "ADMIN OPTION") || confirmed || !databaseExists || !roleExists {
		t.Fatalf("error=%v confirmed=%t database=%t role=%t", err, confirmed, databaseExists, roleExists)
	}
}

// An external transaction replaces a role while cleanup waits for pg_authid.
// The replacement must survive, including its LOGIN and CREATEDB attributes.
// Value: protects=late DROP ROLE failure rolls back every role drop and NOLOGIN change;
// fails_when=role cleanup commits individual drops or leaves surviving roles NOLOGIN;
// why_new=existing cleanup races fail during guards before any DROP ROLE executes;
// seam=none; no_claim=database recovery after the irreversible DROP DATABASE.
func TestDeleteProjectKeepsReplacementDuringRoleCleanup(t *testing.T) {
	cfg := adminConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	locker, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close(context.Background())
	var super bool
	if err = locker.QueryRow(ctx, "SELECT rolsuper FROM pg_roles WHERE rolname=current_user").Scan(&super); err != nil {
		t.Fatal(err)
	}
	if !super {
		t.Skip("locking pg_authid requires superuser")
	}
	for _, scenario := range []string{"replacement", "new powers", "new dependency"} {
		t.Run(scenario, func(t *testing.T) {
			p, _, users := newTestProject(t, cfg)
			extra := p.Name + "_extra"
			if scenario == "new dependency" {
				*users = append(*users, extra)
				mustExec(t, locker, "CREATE ROLE "+ident(extra)+" LOGIN")
				t.Cleanup(func() {
					cleanup, err := pgx.ConnectConfig(context.Background(), cfg)
					if err != nil {
						t.Error(err)
						return
					}
					defer cleanup.Close(context.Background())
					mustExec(t, cleanup, "DROP TABLE IF EXISTS "+ident(p.Name))
				})
			}
			var original uint32
			if err = locker.QueryRow(ctx, "SELECT oid FROM pg_roles WHERE rolname=$1", p.Name).Scan(&original); err != nil {
				t.Fatal(err)
			}
			tx, err := locker.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err = tx.Exec(ctx, "LOCK TABLE pg_authid IN SHARE MODE"); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- DeleteProject(ctx, cfg, p.Name, false, func(Deletion) error { return nil }) }()
			observer, err := pgx.ConnectConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer observer.Close(context.Background())
			for {
				var exists bool
				if err = observer.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)", p.Name).Scan(&exists); err != nil {
					t.Fatal(err)
				}
				if !exists {
					break
				}
				select {
				case err = <-done:
					t.Fatalf("deletion stopped before database drop: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(10 * time.Millisecond):
				}
			}
			if scenario == "replacement" {
				if _, err = tx.Exec(ctx, "DROP ROLE "+ident(p.Name)); err != nil {
					t.Fatal(err)
				}
				if _, err = tx.Exec(ctx, "CREATE ROLE "+ident(p.Name)+" LOGIN CREATEDB"); err != nil {
					t.Fatal(err)
				}
			} else if scenario == "new powers" {
				if _, err = tx.Exec(ctx, "ALTER ROLE "+ident(p.Name)+" CREATEDB"); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err = tx.Exec(ctx, "CREATE TABLE "+ident(p.Name)+" (id int); GRANT SELECT ON "+ident(p.Name)+" TO "+ident(extra)); err != nil {
					t.Fatal(err)
				}
			}
			var replacement uint32
			if err = tx.QueryRow(ctx, "SELECT oid FROM pg_roles WHERE rolname=$1", p.Name).Scan(&replacement); err != nil {
				t.Fatal(err)
			}
			if scenario == "replacement" && replacement == original {
				t.Fatal("test did not replace the role")
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err = <-done:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			var actual uint32
			var login, createdb bool
			if e := observer.QueryRow(ctx, "SELECT oid,rolcanlogin,rolcreatedb FROM pg_roles WHERE rolname=$1", p.Name).Scan(&actual, &login, &createdb); e != nil {
				t.Fatalf("replacement role was lost: %v (deletion error: %v)", e, err)
			}
			if actual != replacement || !login || createdb != (scenario != "new dependency") {
				t.Fatalf("replacement changed: oid=%d login=%t createdb=%t", actual, login, createdb)
			}
			if scenario == "new dependency" {
				var extraLogin bool
				if e := observer.QueryRow(ctx, "SELECT rolcanlogin FROM pg_roles WHERE rolname=$1", extra).Scan(&extraLogin); e != nil || !extraLogin {
					t.Fatalf("late failure lost or disabled dependent role: login=%t error=%v", extraLogin, e)
				}
			}
			reason := "changed"
			if scenario == "new powers" {
				reason = "powers outside"
			} else if scenario == "new dependency" {
				reason = "depend"
			}
			if err == nil || !strings.Contains(err.Error(), "was deleted") || !strings.Contains(err.Error(), reason) || !strings.Contains(err.Error(), "roles may remain") {
				t.Fatalf("missing partial-deletion explanation: %v", err)
			}
		})
	}

}

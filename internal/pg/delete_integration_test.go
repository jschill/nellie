//go:build integration

package pg

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// An external transaction replaces a role while cleanup waits for pg_authid.
// The replacement must survive, including its LOGIN and CREATEDB attributes.
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
	for _, scenario := range []string{"replacement", "new powers"} {
		t.Run(scenario, func(t *testing.T) {
			p, _, _ := newTestProject(t, cfg)
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
			} else {
				if _, err = tx.Exec(ctx, "ALTER ROLE "+ident(p.Name)+" CREATEDB"); err != nil {
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
			if actual != replacement || !login || !createdb {
				t.Fatalf("replacement changed: oid=%d login=%t createdb=%t", actual, login, createdb)
			}
			reason := "changed"
			if scenario == "new powers" {
				reason = "powers outside"
			}
			if err == nil || !strings.Contains(err.Error(), "was deleted") || !strings.Contains(err.Error(), reason) || !strings.Contains(err.Error(), "roles may remain") {
				t.Fatalf("missing partial-deletion explanation: %v", err)
			}
		})
	}

}

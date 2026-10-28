//go:build integration && !windows

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jschill/nellie/internal/pg"
)

func TestDeleteProjectInterruptedPrompt(t *testing.T) {
	if name := os.Getenv("NELLIE_DELETE_PROMPT_CHILD"); name != "" {
		os.Exit(Run([]string{"delete-project", name}, os.Stdin, os.Stdout, os.Stderr))
	}
	dsn := deleteTestDSN(t)
	clearConnEnv(t)
	t.Setenv("DATABASE_URL", dsn)
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p, _ := pg.NewProject("nellie_cli_it_" + strings.ToLower(rand.Text()[:8]))
	if err = pg.CreateProject(ctx, cfg, p, pg.NewPassword()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, e := pgx.ConnectConfig(ctx, cfg)
		if e != nil {
			t.Error(e)
			return
		}
		defer c.Close(ctx)
		c.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{p.Name}.Sanitize())
		c.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{p.Name}.Sanitize())
	})
	cmd := exec.Command(os.Args[0], "-test.run=^TestDeleteProjectInterruptedPrompt$")
	cmd.Env = append(os.Environ(), "NELLIE_DELETE_PROMPT_CHILD="+p.Name, "NELLIE_TEST_DSN=")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	ready := make(chan error, 1)
	go func() {
		var b bytes.Buffer
		buf := make([]byte, 1)
		for {
			n, e := output.Read(buf)
			b.Write(buf[:n])
			if strings.Contains(b.String(), "to confirm deletion: ") {
				ready <- nil
				return
			}
			if e != nil {
				ready <- e
				return
			}
		}
	}()
	select {
	case err = <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("confirmation prompt did not appear")
	}
	if err = cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _ = io.Copy(io.Discard, output); done <- cmd.Wait() }()
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("interrupt reported success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Ctrl-C left the confirmation prompt blocked")
	}
	c, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	var exists bool
	if err = c.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)", p.Name).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("interrupted confirmation deleted the database")
	}
}

// DROP DATABASE is irreversible. Interrupting a blocked role transaction must
// report that progress instead of replacing it with a generic "interrupted".
func TestDeleteProjectInterruptedRoleDrop(t *testing.T) {
	dsn := deleteTestDSN(t)
	clearConnEnv(t)
	t.Setenv("DATABASE_URL", dsn)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(ctx) })
	var super bool
	if err = conn.QueryRow(ctx, "SELECT rolsuper FROM pg_roles WHERE rolname=current_user").Scan(&super); err != nil {
		t.Fatal(err)
	}
	if !super {
		t.Skip("locking pg_authid requires superuser")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pg.NewProject("nellie_cli_it_" + strings.ToLower(rand.Text()[:8]))
	if err = pg.CreateProject(ctx, cfg, p, pg.NewPassword()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{p.Name}.Sanitize())
		conn.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{p.Name}.Sanitize())
	})
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "LOCK TABLE pg_authid IN SHARE MODE"); err != nil {
		t.Fatal(err)
	}
	observer, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(ctx)
	var out, errout lockedBuffer
	done := make(chan int, 1)
	go func() { done <- Run([]string{"delete-project", p.Name}, strings.NewReader(p.Name+"\n"), &out, &errout) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var exists bool
		if err = observer.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)", p.Name).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			break
		}
		if time.Now().After(deadline) {
			tx.Rollback(ctx)
			t.Fatal("database was not dropped before role transaction")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err = syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != exitInterrupted || !strings.Contains(errout.String(), "was deleted") || !strings.Contains(errout.String(), "roles may remain") {
			t.Fatalf("code %d: %s", code, errout.String())
		}
	case <-time.After(5 * time.Second):
		tx.Rollback(ctx)
		t.Fatal("interrupted deletion did not return")
	}
	tx.Rollback(ctx)
}

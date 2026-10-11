//go:build integration

package cli

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestMain sweeps nellie_cli_it_ leftovers before and after the run, like the
// pg package's sweep of nellie_it_: a killed run skips the tests' own
// cleanups, and leftover databases would show up in every later nellie list.
// The two prefixes don't overlap, so the packages can run in parallel.
func TestMain(m *testing.M) {
	dsn := os.Getenv("NELLIE_TEST_DSN")
	if dsn == "" {
		os.Exit(m.Run()) // every integration test skips itself
	}
	sweep(dsn)
	code := m.Run()
	sweep(dsn)
	os.Exit(code)
}

// sweep drops every database and role whose name starts with nellie_cli_it_.
func sweep(dsn string) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sweep: connecting:", err)
		return
	}
	defer conn.Close(ctx)

	for _, q := range []struct{ list, drop string }{
		// Databases first: a role can't be dropped while it has privileges on one.
		{`SELECT datname FROM pg_database WHERE datname LIKE 'nellie\_cli\_it\_%'`, "DROP DATABASE IF EXISTS "},
		{`SELECT rolname FROM pg_roles WHERE rolname LIKE 'nellie\_cli\_it\_%'`, "DROP ROLE IF EXISTS "},
	} {
		rows, err := conn.Query(ctx, q.list)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sweep:", err)
			return
		}
		names, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			fmt.Fprintln(os.Stderr, "sweep:", err)
			return
		}
		for _, name := range names {
			if _, err := conn.Exec(ctx, q.drop+pgx.Identifier{name}.Sanitize()); err != nil {
				fmt.Fprintf(os.Stderr, "sweep: %s%s: %v\n", q.drop, name, err)
			}
		}
	}
}

// Command nellie is a CLI for repeating PostgreSQL administration tasks such
// as adding projects (databases), adding users and managing their access.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"golang.org/x/term"

	"github.com/jschill/nellie/internal/cli"
	"github.com/jschill/nellie/internal/pgadmin"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	app := &cli.App{
		Stdin:        os.Stdin,
		Stdout:       os.Stdout,
		Stderr:       os.Stderr,
		Getenv:       os.Getenv,
		Connect:      pgadmin.NewConnector,
		ReadPassword: readPassword,
	}
	code := app.Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

func readPassword(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("stdin is not a terminal; use --password-stdin")
	}
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	return string(pw), nil
}

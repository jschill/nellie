// Command nellie provisions Postgres projects, users and passwords.
package main

import (
	_ "embed"
	"os"
	"strings"

	"github.com/jschill/nellie/internal/cli"
)

// version is the contents of the VERSION file, compiled into the binary by
// go:embed. That is how a Go program can know its version without a build flag.
//
//go:embed VERSION
var version string

func main() {
	cli.Version = strings.TrimSpace(version)
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

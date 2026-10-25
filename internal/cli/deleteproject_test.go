package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestDeleteProjectUsage(t *testing.T) {
	for _, args := range [][]string{{"delete-project", "-h"}, {"delete-project", "Shop"}, {"delete-project", "shop", "extra"}, {"delete-project", "--force", "shop"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out, errout bytes.Buffer
			code := Run(args, strings.NewReader(""), &out, &errout)
			if args[1] == "-h" {
				if code != exitOK || !strings.Contains(errout.String(), "Type the project name") {
					t.Fatalf("code %d: %s", code, &errout)
				}
			} else if code != exitUsage || strings.Contains(errout.String(), "unknown command") {
				t.Fatalf("code %d: %s", code, &errout)
			}
		})
	}
}

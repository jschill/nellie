package pg

import (
	"context"
	"strings"
	"testing"
)

// Value: protects=the public delete API refuses a missing confirmation callback;
// fails_when=a nil callback proceeds to connect or execute deletion;
// why_new=CLI confirmation tests always supply a callback;
// seam=none; no_claim=database privilege and identity checks.
func TestDeleteProjectRequiresConfirmation(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		err := DeleteProject(context.Background(), nil, "shop", dryRun, nil)
		if err == nil || !strings.Contains(err.Error(), "requires confirmation") {
			t.Fatalf("dryRun=%t: got %v", dryRun, err)
		}
	}
}

func TestDeletionScriptIncludesRoleIdentityGuards(t *testing.T) {
	plan := Deletion{Project: "shop", Roles: []string{"shop"}, databaseOID: 40, roleOIDs: []uint32{41}}
	script := plan.Script()
	for _, want := range []string{"for inspection only", `ALTER ROLE "shop" NOLOGIN;`, "SELECT oid FROM pg_roles WHERE rolname = 'shop'; -- expected OID 41"} {
		if !strings.Contains(script, want) {
			t.Errorf("missing %q in:\n%s", want, script)
		}
	}
	if strings.Index(script, "ALTER ROLE") > strings.Index(script, "DROP ROLE") {
		t.Error("role identity must be protected before dropping")
	}
}

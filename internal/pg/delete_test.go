package pg

import (
	"strings"
	"testing"
)

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

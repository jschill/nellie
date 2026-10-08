package pg

import (
	"encoding/base64"
	"regexp"
	"testing"
)

func TestScramVerifierMatchesPostgres(t *testing.T) {
	// Produced by Postgres 18: CREATE ROLE vec PASSWORD 'correct horse', then
	// read back from pg_authid.rolpassword.
	const want = "SCRAM-SHA-256$4096:HxH41kGE+hor9O0OURtc6Q==$CgVjSV3RFAVIkqfqWqASUDEBstEBhSEhh6/6SKeoZBs=:e1c7UyGxv12rIoXNBgOm6/1OPldnxYZZpxfnasDhJDc="
	salt, err := base64.StdEncoding.DecodeString("HxH41kGE+hor9O0OURtc6Q==")
	if err != nil {
		t.Fatal(err)
	}

	got, err := scramVerifierWithSalt("correct horse", salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestScramVerifierUsesFreshSalt(t *testing.T) {
	a, _ := scramVerifier("same")
	b, _ := scramVerifier("same")
	if a == b {
		t.Error("two verifiers for the same password are identical; salt isn't random")
	}
}

func TestNewPassword(t *testing.T) {
	p := NewPassword()
	if !regexp.MustCompile(`^[A-Z2-7]{26}$`).MatchString(p) {
		t.Errorf("NewPassword() = %q, want 26 characters of A-Z2-7", p)
	}
	if p == NewPassword() {
		t.Error("NewPassword returned the same password twice")
	}
}

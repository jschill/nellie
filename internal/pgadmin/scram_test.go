package pgadmin

import (
	"regexp"
	"testing"
)

func TestHashPasswordWithSalt(t *testing.T) {
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}
	got, err := hashPasswordWithSalt("pencil", salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	const want = "SCRAM-SHA-256$4096:AAECAwQFBgcICQoLDA0ODw==$zHCdol2044/ZyWzPLi7oxApCkamKw9Z+E4U/QApd/5Y=:dd5peBOitVnLNFu7VmwP+HiDaaw4OUCv396eVCWhYiE="
	if got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}

func TestHashPassword(t *testing.T) {
	re := regexp.MustCompile(`^SCRAM-SHA-256\$4096:[A-Za-z0-9+/=]{24}\$[A-Za-z0-9+/=]{44}:[A-Za-z0-9+/=]{44}$`)
	a, err := HashPassword("secret")
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashPassword("secret")
	if err != nil {
		t.Fatal(err)
	}
	if !re.MatchString(a) {
		t.Errorf("unexpected format: %s", a)
	}
	if a == b {
		t.Error("expected different salts for each hash")
	}
	if _, err := HashPassword(""); err == nil {
		t.Error("expected error for empty password")
	}
}

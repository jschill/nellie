package pg

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// scramIterations matches Postgres's default (scram_iterations).
const scramIterations = 4096

// scramSaltLen is the salt size Postgres uses for SCRAM verifiers.
const scramSaltLen = 16

// NewPassword returns a random 26-character password (130 bits of entropy).
// It only uses A-Z and 2-7, so it's safe in URLs and shells without escaping.
func NewPassword() string {
	return rand.Text()
}

// scramVerifier hashes password into the SCRAM-SHA-256 format Postgres stores
// in pg_authid. Sending the verifier instead of the plaintext means the
// password never shows up in server logs, the same trick psql's \password uses.
//
// Postgres runs passwords through SASLprep first; for the ASCII passwords from
// NewPassword that's a no-op, so it's skipped here.
func scramVerifier(password string) (string, error) {
	salt := make([]byte, scramSaltLen)
	rand.Read(salt) // never returns an error since Go 1.24
	return scramVerifierWithSalt(password, salt, scramIterations)
}

func scramVerifierWithSalt(password string, salt []byte, iterations int) (string, error) {
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return "", fmt.Errorf("deriving SCRAM key: %w", err)
	}
	clientKey := hmacSHA256(salted, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	serverKey := hmacSHA256(salted, "Server Key")

	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s",
		iterations, b64(salt), b64(storedKey[:]), b64(serverKey)), nil
}

func hmacSHA256(key []byte, msg string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return mac.Sum(nil)
}

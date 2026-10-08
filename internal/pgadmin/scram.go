package pgadmin

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/text/secure/precis"
)

const (
	scramIterations = 4096
	scramSaltLen    = 16
)

// HashPassword returns a SCRAM-SHA-256 verifier for password in the format
// stored by PostgreSQL. Hashing on the client means the plaintext password is
// never sent to the server or written to its logs.
func HashPassword(password string) (string, error) {
	salt := make([]byte, scramSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}
	return hashPasswordWithSalt(password, salt, scramIterations)
}

func hashPasswordWithSalt(password string, salt []byte, iterations int) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	// Like libpq, fall back to the raw password if SASLprep fails.
	if prepped, err := precis.OpaqueString.String(password); err == nil {
		password = prepped
	}
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return "", fmt.Errorf("deriving key: %w", err)
	}
	clientKey := hmacSHA256(salted, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	serverKey := hmacSHA256(salted, "Server Key")

	enc := base64.StdEncoding
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s",
		iterations,
		enc.EncodeToString(salt),
		enc.EncodeToString(storedKey[:]),
		enc.EncodeToString(serverKey),
	), nil
}

func hmacSHA256(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

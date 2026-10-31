package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
)

// randomBytesLen is 256 bits for session IDs and API tokens.
const randomBytesLen = 32

// newOpaque returns a 256-bit random value, base64url-encoded (43 chars).
func newOpaque() string {
	b := make([]byte, randomBytesLen)
	_, _ = rand.Read(b) // never fails (Go 1.24+)
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeOpaque returns the raw bytes of a value made by newOpaque, or false.
func decodeOpaque(s string) ([]byte, bool) {
	if len(s) != base64.RawURLEncoding.EncodedLen(randomBytesLen) {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != randomBytesLen {
		return nil, false
	}
	return b, true
}

// hashOpaque is the storage key. The inputs are 256-bit random, so a fast hash is
// sufficient (no password-style stretching needed).
func hashOpaque(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return sum[:]
}

// sameHash compares two hashes in constant time.
func sameHash(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// newID returns a 128-bit random hex identifier for users and tokens.
func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// Sealer encrypts small secrets at rest (TOTP secrets). aad binds a ciphertext to its
// owner (the user ID) so a row cannot be copied onto another user.
type Sealer interface {
	Seal(plaintext, aad []byte) ([]byte, error)
	Open(ciphertext, aad []byte) ([]byte, error)
}

type aesGCMSealer struct {
	aead cipher.AEAD
}

// NewAESGCMSealer returns an AES-256-GCM Sealer. key must be 32 bytes from the app key
// file (internal/secrets); it is copied.
func NewAESGCMSealer(key []byte) (Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("auth: sealer key must be 32 bytes")
	}
	block, err := aes.NewCipher(bytes.Clone(key))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesGCMSealer{aead: aead}, nil
}

// Seal returns nonce || ciphertext.
func (s aesGCMSealer) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	_, _ = rand.Read(nonce) // never fails (Go 1.24+)
	return s.aead.Seal(nonce, nonce, plaintext, aad), nil
}

func (s aesGCMSealer) Open(ciphertext, aad []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(ciphertext) < n+s.aead.Overhead() {
		return nil, errors.New("auth: ciphertext too short")
	}
	return s.aead.Open(nil, ciphertext[:n], ciphertext[n:], aad)
}

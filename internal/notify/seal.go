package notify

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"oob-manager/internal/secrets"
)

// PurposeNotify is the HKDF label of the key that seals target secrets
// (secrets.AppKeys.DeriveKey); defined with the other labels in internal/secrets so
// no two purposes can collide.
const PurposeNotify = secrets.PurposeNotify

// ErrUnseal is returned when stored secrets cannot be opened: wrong key, a tampered
// row, or a row moved to another target, kind or URL (the AAD no longer matches).
var ErrUnseal = errors.New("notify: stored secrets cannot be opened (re-enter them)")

// Sealer encrypts target secrets with AES-256-GCM. The additional data binds a
// ciphertext to the target id, kind and URL, so secrets can never be redirected: a
// changed destination makes them undecryptable and they must be entered again.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer builds a sealer from a 32-byte key (AppKeys.DeriveKey(PurposeNotify)).
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("notify: sealing key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("notify: sealer: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("notify: sealer: %w", err)
	}
	return &Sealer{aead: aead}, nil
}

// sealed is the plaintext layout; field names are part of the stored format.
type sealed struct {
	Token    string `json:"t,omitempty"`
	User     string `json:"u,omitempty"`
	Password string `json:"p,omitempty"`
}

func aad(t Target) []byte {
	return []byte("notify/v1|" + t.ID + "|" + string(t.Kind) + "|" + t.URL)
}

// Seal returns nonce||ciphertext of sec for t.
func (s *Sealer) Seal(t Target, sec Secrets) ([]byte, error) {
	pt, err := json.Marshal(sealed{Token: sec.Token.Reveal(), User: sec.User.Reveal(), Password: sec.Password.Reveal()})
	if err != nil {
		return nil, fmt.Errorf("notify: seal: %w", err)
	}
	defer wipe(pt)
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("notify: seal: %w", err)
	}
	return s.aead.Seal(nonce, nonce, pt, aad(t)), nil
}

// Open decrypts blob for t.
func (s *Sealer) Open(t Target, blob []byte) (Secrets, error) {
	n := s.aead.NonceSize()
	if len(blob) < n+s.aead.Overhead() {
		return Secrets{}, ErrUnseal
	}
	pt, err := s.aead.Open(nil, blob[:n], blob[n:], aad(t))
	if err != nil {
		return Secrets{}, ErrUnseal
	}
	defer wipe(pt)
	var raw sealed
	if err := json.Unmarshal(pt, &raw); err != nil {
		return Secrets{}, ErrUnseal
	}
	return Secrets{Token: optSecret(raw.Token), User: optSecret(raw.User), Password: optSecret(raw.Password)}, nil
}

func optSecret(s string) secrets.Secret {
	if s == "" {
		return secrets.Secret{}
	}
	return secrets.New(s)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

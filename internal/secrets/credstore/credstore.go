// Package credstore seals BMC credentials saved from the browser
// (settings_design.md §2): AES-256-GCM under a key derived from the app keys
// (secrets.PurposeBMCCred), with additional data that binds each ciphertext to its
// server, slot, BMC kind, address, port and version. A credential therefore never
// opens for another server, slot or address: changing where a server points makes its
// stored credentials undecryptable, so they must be entered again and can never be
// redirected to a new host.
package credstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"oob-manager/internal/secrets"
)

// KeyBytes is the AES-256 key size.
const (
	KeyBytes   = 32
	nonceBytes = 12
	// KeyID names the key a row was sealed with (bmc_credentials.key_id); only v1 exists.
	KeyID     = "v1"
	aadPrefix = "bmc-cred/v1"
)

// Errors.
var (
	ErrUndecryptable = errors.New("credstore: credential cannot be opened (wrong key, binding or data)")
	ErrBinding       = errors.New("credstore: invalid binding")
	ErrEmpty         = errors.New("credstore: credential is incomplete")
)

// Slot is a closed enum of the credentials a server can hold.
type Slot string

// Slots.
const (
	SlotReadOnly Slot = "readonly" // polling (Redfish reads)
	SlotOperator Slot = "operator" // power, fan floor, serial console, native console launch
	SlotVNC      Slot = "vnc"      // the VNC password (graphical console)
)

// Slots returns every slot in display order (fresh slice).
func Slots() []Slot { return []Slot{SlotReadOnly, SlotOperator, SlotVNC} }

// ParseSlot validates a slot name exactly.
func ParseSlot(s string) (Slot, error) {
	switch Slot(s) {
	case SlotReadOnly, SlotOperator, SlotVNC:
		return Slot(s), nil
	default:
		return "", fmt.Errorf("%w: unknown slot", ErrBinding)
	}
}

// Label is the slot's name in the UI.
func (s Slot) Label() string {
	switch s {
	case SlotReadOnly:
		return "Read-only login"
	case SlotOperator:
		return "Operator login"
	default:
		return "VNC password"
	}
}

// Login reports whether the slot holds a username and password (VNC holds only a password).
func (s Slot) Login() bool { return s != SlotVNC }

// Binding is what a ciphertext is bound to (the AAD).
type Binding struct {
	ServerID string
	Slot     Slot
	Kind     string
	Address  string
	Port     int
	Version  int
}

func (b Binding) validate() error {
	_, slotErr := ParseSlot(string(b.Slot))
	switch {
	case slotErr != nil, b.ServerID == "", b.Kind == "", b.Address == "",
		b.Port < 1 || b.Port > 65535, b.Version < 1,
		strings.Contains(b.ServerID+b.Kind+b.Address, "|"):
		return ErrBinding
	}
	return nil
}

// aad is bmc-cred/v1|server_id|slot|kind|address|port|version.
func (b Binding) aad() []byte {
	return []byte(strings.Join([]string{aadPrefix, b.ServerID, string(b.Slot), b.Kind, b.Address,
		strconv.Itoa(b.Port), strconv.Itoa(b.Version)}, "|"))
}

// Store seals and opens credentials with one key. It holds no other state.
type Store struct {
	aead cipher.AEAD
}

// New builds a Store from a 32-byte key (AppKeys.DeriveKey(secrets.PurposeBMCCred)).
func New(key []byte) (*Store, error) {
	if len(key) != KeyBytes {
		return nil, fmt.Errorf("credstore: key must be %d bytes", KeyBytes)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("credstore: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("credstore: %w", err)
	}
	return &Store{aead: aead}, nil
}

// plain is the sealed JSON document.
type plain struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password"`
}

// Seal encrypts c for b: nonce || ciphertext. A login slot needs a username and a
// password, the VNC slot a password.
func (s *Store) Seal(b Binding, c secrets.Credential) ([]byte, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	if c.Password.IsZero() || (b.Slot.Login() && c.Username == "") {
		return nil, ErrEmpty
	}
	doc, err := json.Marshal(plain{Username: c.Username, Password: c.Password.Reveal()})
	if err != nil {
		return nil, fmt.Errorf("credstore: %w", err)
	}
	defer wipe(doc)
	nonce := make([]byte, nonceBytes, nonceBytes+len(doc)+s.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("credstore: nonce: %w", err)
	}
	return s.aead.Seal(nonce, nonce, doc, b.aad()), nil
}

// Open decrypts blob for b. Any mismatch (key, binding, tampering) is ErrUndecryptable.
func (s *Store) Open(b Binding, blob []byte) (secrets.Credential, error) {
	if err := b.validate(); err != nil {
		return secrets.Credential{}, err
	}
	if len(blob) <= nonceBytes {
		return secrets.Credential{}, ErrUndecryptable
	}
	doc, err := s.aead.Open(nil, blob[:nonceBytes], blob[nonceBytes:], b.aad())
	if err != nil {
		return secrets.Credential{}, ErrUndecryptable
	}
	defer wipe(doc)
	var p plain
	if err := json.Unmarshal(doc, &p); err != nil || p.Password == "" {
		return secrets.Credential{}, ErrUndecryptable
	}
	return secrets.Credential{Username: p.Username, Password: secrets.New(p.Password)}, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

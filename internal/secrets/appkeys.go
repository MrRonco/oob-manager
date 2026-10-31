package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

// AppKeyBytes is the length of each application key (AES-256).
const AppKeyBytes = 32

// AppKeys are the application's own symmetric keys, from the age-encrypted app-keys
// file (`totp_key: <64 hex chars>`). TOTPKey seals TOTP secrets at rest.
type AppKeys struct {
	TOTPKey Secret
}

// String redacts the keys.
func (AppKeys) String() string { return "AppKeys{" + Redacted + "}" }

// GoString redacts the keys.
func (AppKeys) GoString() string { return "AppKeys{" + Redacted + "}" }

// LogValue redacts the keys.
func (AppKeys) LogValue() slog.Value { return slog.StringValue(Redacted) }

type rawAppKeys struct {
	TOTPKey string `yaml:"totp_key"`
}

// LoadAppKeys decrypts and parses the app-keys file. Any failure must abort startup.
func LoadAppKeys(path string, ids []age.Identity) (AppKeys, error) {
	pt, err := DecryptFile(path, ids)
	if err != nil {
		return AppKeys{}, err
	}
	raw := pt.Bytes()
	defer wipe(raw)
	return ParseAppKeys(raw)
}

// ParseAppKeys parses the plaintext document. Errors never include values.
func ParseAppKeys(plaintext []byte) (AppKeys, error) {
	dec := yaml.NewDecoder(bytes.NewReader(plaintext))
	dec.KnownFields(true)
	var raw rawAppKeys
	if err := dec.Decode(&raw); err != nil {
		return AppKeys{}, errors.New("secrets: app-keys file must be a {totp_key: <hex>} map")
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return AppKeys{}, errors.New("secrets: app-keys file must be a single document")
	}
	key, err := hex.DecodeString(raw.TOTPKey)
	defer wipe(key)
	if err != nil || len(key) != AppKeyBytes {
		return AppKeys{}, errors.New("secrets: totp_key must be 64 hex characters (32 bytes)")
	}
	return AppKeys{TOTPKey: FromBytes(key)}, nil
}

// GenerateAppKeys returns a fresh plaintext app-keys document, to be piped straight
// into `age -r <recipient>`; it is never written to disk by this program.
func GenerateAppKeys() ([]byte, error) {
	key := make([]byte, AppKeyBytes)
	defer wipe(key)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return []byte("totp_key: " + hex.EncodeToString(key) + "\n"), nil
}

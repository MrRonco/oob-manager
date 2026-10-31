package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

// Size caps for files read at startup.
const (
	MaxIdentityBytes   = 64 << 10
	MaxCiphertextBytes = 2 << 20
	MaxPlaintextBytes  = 1 << 20
)

// ErrUnknownRef is returned when a credential reference is not in the file.
var ErrUnknownRef = errors.New("secrets: unknown credential reference")

var refPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Credentials is an immutable set of named BMC credentials.
type Credentials struct {
	byRef map[string]Credential
}

// Lookup returns the credential for ref.
func (c Credentials) Lookup(ref string) (Credential, error) {
	cred, ok := c.byRef[ref]
	if !ok {
		return Credential{}, fmt.Errorf("%w: %q", ErrUnknownRef, ref)
	}
	return cred, nil
}

// Refs returns the sorted reference names.
func (c Credentials) Refs() []string {
	refs := make([]string, 0, len(c.byRef))
	for r := range c.byRef {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	return refs
}

// Require fails if any non-empty ref is missing, so startup fails before polling begins.
func (c Credentials) Require(refs ...string) error {
	var missing []string
	for _, r := range refs {
		if _, ok := c.byRef[r]; r != "" && !ok {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrUnknownRef, strings.Join(missing, ", "))
	}
	return nil
}

// LoadIdentities reads an age identity file (X25519 keys, comments allowed).
func LoadIdentities(path string) ([]age.Identity, error) {
	data, err := readCapped(path, MaxIdentityBytes)
	if err != nil {
		return nil, fmt.Errorf("secrets: identity: %w", err)
	}
	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("secrets: identity: not a valid age identity file")
	}
	return ids, nil
}

// DecryptFile decrypts an age file with the given identities.
func DecryptFile(path string, ids []age.Identity) (Secret, error) {
	if len(ids) == 0 {
		return Secret{}, errors.New("secrets: no identities")
	}
	ct, err := readCapped(path, MaxCiphertextBytes)
	if err != nil {
		return Secret{}, fmt.Errorf("secrets: %w", err)
	}
	r, err := age.Decrypt(bytes.NewReader(ct), ids...)
	if err != nil {
		return Secret{}, fmt.Errorf("secrets: decrypt %s: %w", path, err)
	}
	pt, err := io.ReadAll(io.LimitReader(r, MaxPlaintextBytes+1))
	defer wipe(pt)
	if err != nil {
		return Secret{}, fmt.Errorf("secrets: decrypt %s: %w", path, err)
	}
	if len(pt) > MaxPlaintextBytes {
		return Secret{}, fmt.Errorf("secrets: %s plaintext too large", path)
	}
	return FromBytes(pt), nil
}

// LoadCredentials decrypts credPath with the identity at idPath and parses it.
// Any failure (wrong key, corrupt file, bad schema) must abort startup.
func LoadCredentials(credPath, idPath string) (Credentials, error) {
	ids, err := LoadIdentities(idPath)
	if err != nil {
		return Credentials{}, err
	}
	pt, err := DecryptFile(credPath, ids)
	if err != nil {
		return Credentials{}, err
	}
	raw := pt.Bytes()
	defer wipe(raw)
	return ParseCredentials(raw)
}

type rawCredential struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// ParseCredentials parses `{ref: {username, password}}` (YAML or JSON; username is
// optional for password-only entries such as VNC). Error messages
// never include values from the document.
func ParseCredentials(plaintext []byte) (Credentials, error) {
	dec := yaml.NewDecoder(bytes.NewReader(plaintext))
	dec.KnownFields(true)
	var raw map[string]rawCredential
	if err := dec.Decode(&raw); err != nil {
		return Credentials{}, errors.New("secrets: credential file is not a {ref: {username, password}} map")
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Credentials{}, errors.New("secrets: credential file must be a single document")
	}
	byRef := make(map[string]Credential, len(raw))
	for ref, rc := range raw {
		if !refPattern.MatchString(ref) {
			return Credentials{}, errors.New("secrets: credential reference has invalid characters")
		}
		// A username is optional: VNC entries carry only a password. Drivers that log in
		// refuse an entry without one (see Credential.HasLogin).
		if rc.Password == "" {
			return Credentials{}, fmt.Errorf("secrets: credential %q needs a password", ref)
		}
		byRef[ref] = Credential{Username: rc.Username, Password: New(rc.Password)}
	}
	if len(byRef) == 0 {
		return Credentials{}, errors.New("secrets: credential file is empty")
	}
	return Credentials{byRef: byRef}, nil
}

func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- paths come from validated config
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s too large", path)
	}
	return data, nil
}

// wipe zeroes a scratch buffer this package owns (best effort; Go may have copied it).
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

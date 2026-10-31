package firstrun

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"filippo.io/age"

	"oob-manager/internal/secrets"
)

// Names of the generated key set inside the data directory.
const (
	keysDir      = "keys"
	identityName = "age-identity"
	appKeysName  = "app-keys.age"
	markerName   = "BACKUP-PENDING"
)

// ErrKeysMissing means no keys are reachable while the database already holds sealed
// data: generating new keys would make all of it unreadable.
var ErrKeysMissing = errors.New("firstrun: the database holds accounts or sealed secrets but no app keys " +
	"were found; mount the original age identity and app-keys.age (or restore " + keysDir + "/ in the data volume)")

// KeyPaths are the generated key files of a data directory.
type KeyPaths struct {
	Identity, AppKeys string
}

// KeyPathsIn returns the key file paths inside dataDir.
func KeyPathsIn(dataDir string) KeyPaths {
	dir := filepath.Join(dataDir, keysDir)
	return KeyPaths{Identity: filepath.Join(dir, identityName), AppKeys: filepath.Join(dir, appKeysName)}
}

// EnsureKeys makes sure dataDir holds a complete generated key set. An existing set is
// reused; half a set is an error; with no set, keys are generated only when fresh
// reports a new database (ErrKeysMissing otherwise). generated is true when this call
// created them, and then the backup notice is pending.
func EnsureKeys(dataDir string, fresh func() (bool, error)) (generated bool, err error) {
	p := KeyPathsIn(dataDir)
	all, none, missing, err := setState(p.Identity, p.AppKeys)
	switch {
	case err != nil:
		return false, err
	case all:
		return false, nil
	case !none:
		return false, fmt.Errorf("firstrun: incomplete key set in %s: %s is missing; restore it from your backup "+
			"(new keys would make the stored secrets unreadable)", filepath.Dir(p.Identity), filepath.Base(missing))
	}
	ok, err := fresh()
	if err != nil {
		return false, err
	}
	if !ok {
		return false, ErrKeysMissing
	}
	if err = cleanTemp(dataDir, keysDir); err != nil {
		return false, err
	}
	files, err := newKeyFiles(time.Now())
	if err != nil {
		return false, err
	}
	if err = writeSet(dataDir, keysDir, 0o700, files); err != nil {
		return false, err
	}
	return true, nil
}

// newKeyFiles builds a fresh identity, the app keys sealed to it, and the notice marker.
func newKeyFiles(now time.Time) ([]file, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("firstrun: identity: %w", err)
	}
	doc, err := secrets.GenerateAppKeys()
	if err != nil {
		return nil, fmt.Errorf("firstrun: app keys: %w", err)
	}
	sealed, err := seal(doc, id.Recipient())
	wipe(doc)
	if err != nil {
		return nil, err
	}
	idText := fmt.Sprintf("# created: %s by oob-manager (first start)\n# public key: %s\n%s\n",
		now.UTC().Format(time.RFC3339), id.Recipient(), id)
	return []file{
		{identityName, []byte(idText), 0o400},
		{appKeysName, sealed, 0o400},
		{markerName, []byte("Back up " + identityName + ", then acknowledge the notice in the UI.\n"), 0o600},
	}, nil
}

func seal(plaintext []byte, r age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, fmt.Errorf("firstrun: seal app keys: %w", err)
	}
	if _, err := io.Copy(w, bytes.NewReader(plaintext)); err != nil {
		return nil, fmt.Errorf("firstrun: seal app keys: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("firstrun: seal app keys: %w", err)
	}
	return buf.Bytes(), nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

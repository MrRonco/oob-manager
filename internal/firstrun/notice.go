package firstrun

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// Notice is the "back up the generated identity" reminder: pending while the marker
// written with the keys exists.
type Notice struct {
	dir string
}

// NewNotice returns the notice of dataDir's generated keys.
func NewNotice(dataDir string) Notice { return Notice{dir: filepath.Join(dataDir, keysDir)} }

// Pending reports whether the generated keys have not been acknowledged yet.
func (n Notice) Pending() bool {
	_, err := os.Stat(filepath.Join(n.dir, markerName))
	return err == nil
}

// IdentityPath is the generated identity the notice is about.
func (n Notice) IdentityPath() string { return filepath.Join(n.dir, identityName) }

// Dismiss removes the marker. The key directory is owner-only (0700, 0400 files); its
// mode is set to 0700 again first, so the removal works even if an operator made the
// directory read-only. It is left at 0700 (owner-only either way).
func (n Notice) Dismiss() error {
	if !n.Pending() {
		return nil
	}
	if err := os.Chmod(n.dir, 0o700); err != nil { //nolint:gosec // G302: owner-only directory
		return err
	}
	err := os.Remove(filepath.Join(n.dir, markerName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

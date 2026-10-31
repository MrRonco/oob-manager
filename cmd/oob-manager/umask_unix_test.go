//go:build linux || darwin

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"oob-manager/internal/store"
)

// TestProcessUmaskMakesDatabaseOwnerOnly: with the process umask (set in main) the
// database and its WAL and SHM files are created 0600 (plan 06 §3.1; the database holds sealed secrets,
// token hashes and the audit log).
func TestProcessUmaskMakesDatabaseOwnerOnly(t *testing.T) {
	old := restrictUmask()
	t.Cleanup(func() { unix.Umask(old) })
	dir := t.TempDir()
	db, err := store.Open(context.Background(), filepath.Join(dir, "oob-manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, name := range []string{"oob-manager.db", "oob-manager.db-wal", "oob-manager.db-shm"} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("%s mode %o, want 600", name, got)
		}
	}
}

package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestBackupWritesAConsistentCopy: a backup taken on its own connection, while
// the writer pool is open, holds the same schema version and audit rows (plan 06 §3.6).
func TestBackupWritesAConsistentCopy(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	src := filepath.Join(dir, "oob-manager.db")
	db, err := Open(ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	seedAudit(t, db, []AuditRecord{{Principal: "morgan", Action: "auth.login", Result: "ok"},
		{Principal: "system", Action: "app.start", Result: "ok"}})
	want, err := db.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(dir, "backup.db")
	if err = Backup(ctx, src, dst); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if err = Backup(ctx, src, dst); err == nil {
		t.Fatal("Backup overwrote an existing file")
	}
	// Created owner-only by Backup itself, whatever the process umask (review low 2).
	if fi, serr := os.Stat(dst); serr != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode: %v %v, want 0600", fi.Mode().Perm(), serr)
	}
	// A symlink planted at the destination is never followed.
	link := filepath.Join(dir, "link.db")
	target := filepath.Join(dir, "elsewhere.db")
	if err = os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err = Backup(ctx, src, link); err == nil {
		t.Fatal("Backup wrote through a symlink")
	}
	if _, serr := os.Lstat(target); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("the symlink target was created: %v", serr)
	}

	bk, err := OpenReadOnly(ctx, dst)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bk.Close() })
	got, err := bk.SchemaVersion(ctx)
	if err != nil || got != want {
		t.Fatalf("backup schema %d (%v), want %d", got, err, want)
	}
	rows, err := bk.Audit().List(ctx, 0, 10)
	if err != nil || len(rows) != 2 || rows[1].Action != "app.start" {
		t.Fatalf("backup audit rows = %+v (%v)", rows, err)
	}
}

func TestBackupRefusesBadPaths(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	src := filepath.Join(dir, "oob.db")
	db, err := Open(ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, p := range []string{"", "relative.db", filepath.Join(dir, "x?mode=rw.db"), filepath.Join(dir, "x%3Fmode=rw.db")} {
		if err := Backup(ctx, src, p); err == nil {
			t.Errorf("Backup to %q accepted", p)
		}
	}
	if err := Backup(ctx, filepath.Join(dir, "missing.db"), filepath.Join(dir, "b.db")); err == nil {
		t.Error("Backup of a missing database succeeded (it must not create the source)")
	}
	if _, err := os.Stat(filepath.Join(dir, "missing.db")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the missing source was created: %v", err)
	}
}

// TestOpenReadOnlyRefusesPercent: a % in a path would be decoded in the file: URI
// (%3F becomes ?), so it is refused like ? and # (review L6).
func TestOpenReadOnlyRefusesPercent(t *testing.T) {
	if _, err := OpenReadOnly(context.Background(), filepath.Join(t.TempDir(), "a%3Fmode=rwc.db")); err == nil {
		t.Fatal("a path with % was accepted")
	}
	if _, err := Open(context.Background(), filepath.Join(t.TempDir(), "b%23.db")); err == nil {
		t.Fatal("Open accepted a path with %")
	}
}

// TestOpenReadOnlyDistrustsSchema: copies opened for verification may be untrusted, so
// the read-only connection runs with trusted_schema off (review L5).
func TestOpenReadOnlyDistrustsSchema(t *testing.T) {
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "oob.db")
	db, err := Open(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	ro, err := OpenReadOnly(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	var on int
	if err := ro.sql.QueryRowContext(ctx, `PRAGMA trusted_schema`).Scan(&on); err != nil || on != 0 {
		t.Fatalf("trusted_schema = %d (%v), want 0", on, err)
	}
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Backup writes a consistent, compacted copy of the database at src to dst (plan 06
// §3.6, `oob-manager backup`) with VACUUM INTO, which only reads the source, holds no lock
// for long and sees one snapshot even while serve keeps writing. It uses its own
// connection: SQLite opens the destination with the source connection's flags, so the
// read-only pool cannot write it. mode=rw never creates src, and no migration or pragma
// runs on it. dst must be an absolute path that does not exist (SQLite refuses to
// overwrite). The copy holds sealed secrets, token hashes and the audit log, but never the
// age identity or the app keys, which live outside the database.
func Backup(ctx context.Context, src, dst string) error {
	for _, p := range []string{src, dst} {
		if p == "" || !filepath.IsAbs(p) || strings.ContainsAny(p, "?#%") {
			return fmt.Errorf("store: backup path %q must be absolute without ?, # or %% (they would be read as URI syntax)", p)
		}
	}
	// Create the destination ourselves, empty and owner-only, before SQLite writes into it
	// (VACUUM INTO accepts an empty existing file): O_CREATE|O_EXCL fails on any existing
	// path, a symlink included, so nothing planted there is followed, and the copy is 0600
	// whatever the umask. SQLite reopens it by name, so afterwards it must still be the
	// same regular file.
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the operator-chosen backup path, checked absolute
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("store: backup %s already exists", dst)
		}
		return fmt.Errorf("store: backup %s: %w", dst, err)
	}
	created, err := f.Stat()
	_ = f.Close()
	if err != nil {
		return errors.Join(fmt.Errorf("store: backup %s: %w", dst, err), os.Remove(dst))
	}
	if err := vacuumInto(ctx, src, dst); err != nil {
		return errors.Join(err, os.Remove(dst))
	}
	if now, err := os.Lstat(dst); err != nil || !now.Mode().IsRegular() || !os.SameFile(created, now) {
		return fmt.Errorf("store: backup %s was replaced while it was written; do not trust it", dst)
	}
	return nil
}

// vacuumInto runs VACUUM INTO on its own connection to src (mode=rw never creates it).
func vacuumInto(ctx context.Context, src, dst string) error {
	db, err := sql.Open("sqlite", "file:"+src+"?mode=rw&_pragma=busy_timeout(5000)")
	if err != nil {
		return fmt.Errorf("store: backup: open %s: %w", src, err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, dst); err != nil {
		return fmt.Errorf("store: backup into %s: %w", dst, err)
	}
	return nil
}

// SchemaVersion returns the highest applied migration version of this database.
func (d *ReadDB) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := d.sql.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("store: schema version: %w", err)
	}
	return v, nil
}

// Audit returns the audit chain on the read-only connection, for an offline chain check
// (`oob-manager verify-audit`). Append fails here: the connection is query-only.
func (d *ReadDB) Audit() AuditRepository { return auditRepo{d.sql} }

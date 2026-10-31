package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/store"
)

// backupFileMode is the mode of a backup file: it holds sealed secrets, token hashes and
// the audit log (security.md §3m), so it is owner-only even when the caller's umask is wide.
const backupFileMode = 0o600

// backupCmd writes a consistent copy of the database into dir (plan 06 §3.6):
// `oob-manager backup [-config path] <dir>`. It copies nothing else: config.yaml and the
// .age files are the installer's own files, and the age identity is never included. It verifies
// the copy's audit chain and prints its schema version and head hash, the value to
// compare with the log server's last row_hash after a restore (runbook drill 7).
func backupCmd(e env, args []string) error {
	fs, cfgPath := newFlagSet("backup", e.errOut)
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if err = wantPositional("backup", pos, 1); err != nil {
		return fmt.Errorf("%w (usage: backup [-config path] <directory>)", err)
	}
	dir := pos[0]
	if err = checkBackupDir(dir); err != nil {
		return err
	}
	cfg, err := loadCLIConfig(e, *cfgPath)
	if err != nil {
		return err
	}
	dst := filepath.Join(dir, "oob-manager-"+time.Now().UTC().Format("20060102T150405Z")+".db")
	if err := store.Backup(e.ctx, cfg.Storage.DBPath, dst); err != nil {
		return err
	}
	// store.Backup created the file itself (O_CREATE|O_EXCL, 0600) and checked it is still
	// that file; this check and the chmod are belt and braces for a wider umask.
	if fi, lerr := os.Lstat(dst); lerr != nil || !fi.Mode().IsRegular() { //nolint:gosec // G703: operator-chosen directory (trusted shell), checked absolute
		return fmt.Errorf("backup: %s is not the regular file that was written; check the directory", dst)
	}
	if err := os.Chmod(dst, backupFileMode); err != nil { //nolint:gosec // G703: operator-chosen directory (trusted shell), checked absolute
		return fmt.Errorf("backup: %s written, but its mode could not be set to 0600: %w", dst, err)
	}
	_, _ = fmt.Fprintf(e.out, "backup: %s\n", dst)
	if err := reportDB(e, dst); err != nil {
		return fmt.Errorf("backup: %s was written but does not verify: %w", dst, err)
	}
	return nil
}

// checkBackupDir wants an existing absolute directory (in the container, a path under
// the /data volume: the root filesystem is read-only and /tmp is a small tmpfs).
func checkBackupDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("backup: %q must be an absolute directory path", dir)
	}
	fi, err := os.Stat(dir) //nolint:gosec // G703: operator-chosen directory (trusted shell), checked absolute
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("backup: %s is not a directory", dir)
	}
	return nil
}

// verifyAuditCmd checks an audit chain offline (plan 06 §3.6):
// `oob-manager verify-audit [-config path] [database]`, the configured database by default.
// It only reads (a query-only connection), so it is safe beside a running serve.
func verifyAuditCmd(e env, args []string) error {
	fs, cfgPath := newFlagSet("verify-audit", e.errOut)
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return errors.New("verify-audit: expected at most one database path")
	}
	path := ""
	if len(pos) == 1 {
		path = pos[0]
	} else {
		cfg, err := loadCLIConfig(e, *cfgPath)
		if err != nil {
			return err
		}
		path = cfg.Storage.DBPath
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("verify-audit: %q must be an absolute path", path)
	}
	if _, err := os.Stat(path); err != nil { //nolint:gosec // G703: operator-chosen database path (trusted shell), checked absolute
		return fmt.Errorf("verify-audit: %w", err)
	}
	return reportDB(e, path)
}

// reportDB prints the schema version and the verified audit chain of the database at
// path, or returns the first broken link (*audit.TamperError).
func reportDB(e env, path string) error {
	ctx, cancel := context.WithTimeout(e.ctx, 10*time.Minute)
	defer cancel()
	db, err := store.OpenReadOnly(ctx, path)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	schema, err := db.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(e.out, "schema: %d\n", schema)
	res, err := audit.Verify(ctx, db.Audit(), 0)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(e.out, "audit: chain verified, %d rows, head %s\n", res.Count, res.Head)
	return nil
}

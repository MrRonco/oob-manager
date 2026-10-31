package main

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	backupLine = regexp.MustCompile(`(?m)^backup: (/\S+/oob-manager-\d{8}T\d{6}Z\.db)$`)
	headLine   = regexp.MustCompile(`(?m)^audit: chain verified, (\d+) rows, head ([0-9a-f]{64})$`)
)

// TestBackupAndVerifyAudit: `backup` writes a 0600 copy of the database (never the keys)
// and verifies its audit chain; `verify-audit` checks a copy or the live database offline
// and reports the same head hash (plan 06 §3.6).
func TestBackupAndVerifyAudit(t *testing.T) {
	d, _ := bootstrapped(t)
	dir := t.TempDir()
	rc, out, errOut := runCLI(t, "backup", "-config", d.configPath, dir)
	if rc != 0 {
		t.Fatalf("backup: %d %s", rc, errOut)
	}
	m := backupLine.FindStringSubmatch(out)
	h := headLine.FindStringSubmatch(out)
	if m == nil || h == nil || !strings.Contains(out, "schema: ") {
		t.Fatalf("backup output:\n%s", out)
	}
	fi, err := os.Stat(m[1])
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("backup mode %o, want 600", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("backup wrote %d files, want only the database copy", len(entries))
	}
	// No key material inside the copy: not the age identity, not the sealed app keys.
	raw, err := os.ReadFile(m[1]) //nolint:gosec // G304: the path the command just printed, in a test temp dir
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"identity", "app-keys.age"} {
		key, err := os.ReadFile(filepath.Join(d.dir, name)) //nolint:gosec // G304: fixed names in the test deployment dir
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, bytes.TrimSpace(key)) {
			t.Errorf("the backup contains the bytes of %s", name)
		}
	}
	if bytes.Contains(raw, []byte("AGE-SECRET-KEY-")) {
		t.Error("the backup contains an age secret key")
	}

	rc, out2, errOut := runCLI(t, "verify-audit", m[1])
	if rc != 0 || !strings.Contains(out2, h[2]) {
		t.Fatalf("verify-audit of the copy: %d\n%s%s", rc, out2, errOut)
	}
	rc, out3, errOut := runCLI(t, "verify-audit", "-config", d.configPath)
	if rc != 0 || headLine.FindStringSubmatch(out3) == nil {
		t.Fatalf("verify-audit of the live database: %d\n%s%s", rc, out3, errOut)
	}
}

// TestVerifyAuditDetectsTampering: an edited audit row in a copy fails the check.
func TestVerifyAuditDetectsTampering(t *testing.T) {
	d, _ := bootstrapped(t)
	dir := t.TempDir()
	rc, out, errOut := runCLI(t, "backup", "-config", d.configPath, dir)
	if rc != 0 {
		t.Fatalf("backup: %d %s", rc, errOut)
	}
	path := backupLine.FindStringSubmatch(out)[1]
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DROP TRIGGER audit_log_no_update`, `UPDATE audit_log SET principal = 'mallory' WHERE seq = 1`} {
		if _, err := db.ExecContext(context.Background(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	_ = db.Close()
	rc, out, errOut = runCLI(t, "verify-audit", path)
	if rc == 0 || !strings.Contains(errOut, "seq 1") {
		t.Fatalf("tampered chain verified: %d\n%s%s", rc, out, errOut)
	}
}

func TestBackupRefusals(t *testing.T) {
	d, _ := bootstrapped(t)
	file := filepath.Join(t.TempDir(), "plain-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"no directory":       {"backup", "-config", d.configPath},
		"relative directory": {"backup", "-config", d.configPath, "relative/dir"},
		"missing directory":  {"backup", "-config", d.configPath, filepath.Join(t.TempDir(), "nope")},
		"not a directory":    {"backup", "-config", d.configPath, file},
		"two arguments":      {"backup", "-config", d.configPath, t.TempDir(), t.TempDir()},
		"verify bad path":    {"verify-audit", "relative.db"},
		"verify missing db":  {"verify-audit", filepath.Join(t.TempDir(), "missing.db")},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if rc, _, _ := runCLI(t, args...); rc == 0 {
				t.Fatalf("%v succeeded", args)
			}
		})
	}
}

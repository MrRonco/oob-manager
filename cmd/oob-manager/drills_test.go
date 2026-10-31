package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"context"
)

// Recovery drills (plan 06 §3.6; deploy/README "Recovery runbook"). Drills 3, 4 and 6
// are covered where the behaviour lives (fan TestCrashRestart, maint
// TestOpenEndedReminder, bmcreset TestStartRearmsOpenWindowsAndClosesExpiredOnes), drill 8
// by TestAdminRecover; drill 5 is a runbook reading only.

// TestDrill1LostDatabase: with the database gone, the next start makes an empty one
// (no accounts, no tokens) and bootstrap-admin works again; config.yaml and the keys
// are untouched.
func TestDrill1LostDatabase(t *testing.T) {
	d, _ := bootstrapped(t)
	if rc, out, _ := runCLI(t, "token", "create", "-config", d.configPath, "-name", "dash"); rc != 0 || out == "" {
		t.Fatal("setup: token create failed")
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(d.dbPath + suffix)
	}
	rc, out, errOut := runCLI(t, "token", "list", "-config", d.configPath)
	if rc == 0 && strings.Contains(out, "dash") {
		t.Fatalf("token survived the lost database:\n%s%s", out, errOut)
	}
	// An empty database: the first admin can be created again.
	inR, inW := io.Pipe()
	var bout, berr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- run([]string{"oob-manager", "bootstrap-admin", "-config", d.configPath, "-username", "admin"},
			cliEnv(context.Background(), inR, &bout, &berr))
	}()
	go func() { _, _ = io.WriteString(inW, adminPassword+"\n"+adminPassword+"\n") }()
	waitUntil(t, "enrollment printed again", func() bool { return secretLine.MatchString(bout.String()) })
	_ = inW.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("bootstrap-admin did not end after stdin closed")
	}
}

// TestDrill2LostKeys: without the age identity or the app keys the app refuses to start
// (by design, no fallback that would generate new keys for an existing database).
func TestDrill2LostKeys(t *testing.T) {
	for _, name := range []string{"identity", "app-keys.age"} {
		t.Run(name, func(t *testing.T) {
			d, _ := bootstrapped(t)
			if err := os.Remove(filepath.Join(d.dir, name)); err != nil {
				t.Fatal(err)
			}
			rc, _, errOut := runCLI(t, "token", "list", "-config", d.configPath)
			if rc == 0 {
				t.Fatalf("started without %s", name)
			}
			if !strings.Contains(errOut, name) {
				t.Errorf("the error does not name the missing file %s: %s", name, errOut)
			}
			for _, gen := range []string{"keys", "tls", "store-install"} {
				if _, err := os.Stat(filepath.Join(d.dir, gen)); err == nil {
					t.Errorf("%s was generated after losing %s", gen, name)
				}
			}
		})
	}
}

// TestDrill7OlderBackup: an older backup verifies on its own, but its head differs from
// the live chain's: the runbook compares the restored head with the log server's last
// row_hash to see what is missing.
func TestDrill7OlderBackup(t *testing.T) {
	d, _ := bootstrapped(t)
	dir := t.TempDir()
	rc, out, errOut := runCLI(t, "backup", "-config", d.configPath, dir)
	if rc != 0 {
		t.Fatalf("backup: %s", errOut)
	}
	old := headLine.FindStringSubmatch(out)
	if rc2, _, _ := runCLI(t, "token", "create", "-config", d.configPath, "-name", "later"); rc2 != 0 {
		t.Fatal("token create after the backup failed")
	}
	rc, live, _ := runCLI(t, "verify-audit", "-config", d.configPath)
	now := headLine.FindStringSubmatch(live)
	if rc != 0 || old == nil || now == nil || old[2] == now[2] || old[1] >= now[1] {
		t.Fatalf("backup head %v, live head %v", old, now)
	}
	rc, again, _ := runCLI(t, "verify-audit", backupLine.FindStringSubmatch(out)[1])
	if rc != 0 || !strings.Contains(again, old[2]) {
		t.Fatalf("the older backup does not verify on its own:\n%s", again)
	}
}

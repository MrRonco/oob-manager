package firstrun

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/secrets"
)

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

func TestCheckWritable(t *testing.T) {
	dir := t.TempDir()
	if err := CheckWritable(dir); err != nil {
		t.Fatalf("writable dir: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("probe left %d files behind", len(entries))
	}
	if err := CheckWritable(filepath.Join(dir, "missing")); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing dir: %v", err)
	}
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckWritable(file); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("file: %v", err)
	}
	if runtime.GOOS != "windows" && os.Getuid() != 0 {
		ro := filepath.Join(dir, "ro")
		if err := os.Mkdir(ro, 0o500); err != nil { //nolint:gosec // G302: a test directory
			t.Fatal(err)
		}
		err := CheckWritable(ro)
		if err == nil || !strings.Contains(err.Error(), "not writable") || !strings.Contains(err.Error(), "chown") {
			t.Errorf("read-only dir: %v", err)
		}
	}
}

func fresh(b bool) func() (bool, error) { return func() (bool, error) { return b, nil } }

func TestEnsureKeysGeneratesOnceOnAFreshInstall(t *testing.T) {
	data := t.TempDir()
	p := KeyPathsIn(data)
	gen, err := EnsureKeys(data, fresh(true))
	if err != nil || !gen {
		t.Fatalf("EnsureKeys = %v, %v", gen, err)
	}
	if m := mode(t, filepath.Dir(p.Identity)); m != 0o700 {
		t.Errorf("keys dir mode %o, want 700", m)
	}
	for _, f := range []string{p.Identity, p.AppKeys} {
		if m := mode(t, f); m != 0o400 {
			t.Errorf("%s mode %o, want 400", filepath.Base(f), m)
		}
	}
	ids, err := secrets.LoadIdentities(p.Identity)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if _, kerr := secrets.LoadAppKeys(p.AppKeys, ids); kerr != nil {
		t.Fatalf("app keys do not open with the identity: %v", kerr)
	}
	if !NewNotice(data).Pending() {
		t.Error("no backup notice after generating keys")
	}
	before, _ := os.ReadFile(p.Identity)
	gen, err = EnsureKeys(data, fresh(false)) // a later start: the DB has data now
	if err != nil || gen {
		t.Fatalf("second EnsureKeys = %v, %v (must reuse, never regenerate)", gen, err)
	}
	after, _ := os.ReadFile(p.Identity)
	if string(before) != string(after) {
		t.Error("identity changed on the second start")
	}
}

func TestEnsureKeysRefusesWhenTheDatabaseHasData(t *testing.T) {
	data := t.TempDir()
	_, err := EnsureKeys(data, fresh(false))
	if !errors.Is(err, ErrKeysMissing) {
		t.Fatalf("err = %v, want ErrKeysMissing", err)
	}
	if _, serr := os.Stat(filepath.Join(data, "keys")); !errors.Is(serr, os.ErrNotExist) {
		t.Error("keys directory created although generation was refused")
	}
}

func TestEnsureKeysRefusesAPartialSet(t *testing.T) {
	data := t.TempDir()
	if _, err := EnsureKeys(data, fresh(true)); err != nil {
		t.Fatal(err)
	}
	p := KeyPathsIn(data)
	if err := os.Chmod(filepath.Dir(p.AppKeys), 0o700); err != nil { //nolint:gosec // G302: a test directory
		t.Fatal(err)
	}
	if err := os.Remove(p.AppKeys); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureKeys(data, fresh(true)); err == nil || !strings.Contains(err.Error(), "app-keys.age") {
		t.Fatalf("partial set: err = %v", err)
	}
	if _, err := os.Stat(p.AppKeys); !errors.Is(err, os.ErrNotExist) {
		t.Error("a partial set was completed instead of refused")
	}
}

func TestEnsureKeysFreshnessErrorStops(t *testing.T) {
	boom := errors.New("db locked")
	if _, err := EnsureKeys(t.TempDir(), func() (bool, error) { return false, boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}

func TestEnsureKeysIgnoresAnAbandonedTempDir(t *testing.T) {
	data := t.TempDir()
	if err := os.Mkdir(filepath.Join(data, ".keys-tmp-123"), 0o700); err != nil { //nolint:gosec // G302: a test directory
		t.Fatal(err)
	}
	if _, err := EnsureKeys(data, fresh(true)); err != nil {
		t.Fatalf("EnsureKeys: %v", err)
	}
	if _, err := os.Stat(filepath.Join(data, ".keys-tmp-123")); !errors.Is(err, os.ErrNotExist) {
		t.Error("abandoned temp dir not cleaned up")
	}
}

func TestNoticeDismiss(t *testing.T) {
	data := t.TempDir()
	n := NewNotice(data)
	if n.Pending() {
		t.Fatal("pending without generated keys")
	}
	if _, err := EnsureKeys(data, fresh(true)); err != nil {
		t.Fatal(err)
	}
	if !n.Pending() || n.IdentityPath() != KeyPathsIn(data).Identity {
		t.Fatalf("pending %v path %q", n.Pending(), n.IdentityPath())
	}
	if err := n.Dismiss(); err != nil {
		t.Fatalf("Dismiss: %v", err)
	}
	if n.Pending() {
		t.Error("still pending after Dismiss")
	}
	if err := n.Dismiss(); err != nil {
		t.Errorf("second Dismiss: %v", err)
	}
	if _, err := os.Stat(KeyPathsIn(data).Identity); err != nil {
		t.Errorf("Dismiss touched the identity: %v", err)
	}
}

func TestEnsureCert(t *testing.T) {
	data := t.TempDir()
	c, err := EnsureCert(data, []string{"localhost", "192.0.2.20"})
	if err != nil || !c.Generated || len(c.SHA256) != 64 {
		t.Fatalf("EnsureCert = %+v, %v", c, err)
	}
	if m := mode(t, c.KeyFile); m != 0o400 {
		t.Errorf("key mode %o", m)
	}
	if m := mode(t, c.CertFile); m != 0o444 {
		t.Errorf("cert mode %o", m)
	}
	again, err := EnsureCert(data, []string{"other.example.test"})
	if err != nil || again.Generated || again.SHA256 != c.SHA256 {
		t.Fatalf("second EnsureCert = %+v, %v (must reuse)", again, err)
	}
	if err := os.Chmod(filepath.Dir(c.KeyFile), 0o700); err != nil { //nolint:gosec // G302: a test directory
		t.Fatal(err)
	}
	if err := os.Remove(c.KeyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureCert(data, []string{"localhost"}); err == nil {
		t.Fatal("a certificate without its key was accepted or completed")
	}
}

// A generated certificate near (or past) its end must be reported at startup (L3).
func TestCertExpiry(t *testing.T) {
	data := t.TempDir()
	c, err := EnsureCert(data, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if c.NotAfter.IsZero() {
		t.Fatal("NotAfter not reported")
	}
	if c.ExpiresSoon(time.Now()) {
		t.Error("a new certificate reported as expiring")
	}
	if !c.ExpiresSoon(c.NotAfter.Add(-29*24*time.Hour)) || !c.ExpiresSoon(c.NotAfter.Add(time.Hour)) {
		t.Error("a certificate within 30 days of its end (or past it) not reported")
	}
}

func TestSetupCode(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	s, code, err := NewSetup(func() time.Time { return now }, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.ReplaceAll(code, "-", "")) != 32 || strings.Count(code, "-") != 7 {
		t.Fatalf("code %q: want 8 groups of 4", code)
	}
	if s.check("WRONG-CODE") || s.check("") {
		t.Error("a wrong code passed")
	}
	if !s.check(code) || !s.check(strings.ToLower(strings.ReplaceAll(code, "-", " "))) {
		t.Error("the right code (any case, spaces or dashes) failed")
	}
	if !s.ExpiresAt().Equal(now.Add(time.Hour)) {
		t.Errorf("expires %v", s.ExpiresAt())
	}
	s.Burn()
	if s.check(code) {
		t.Error("code passed after Burn")
	}
	s2, code2, _ := NewSetup(func() time.Time { return now }, time.Hour)
	if code2 == code {
		t.Error("two setups produced the same code")
	}
	now = now.Add(time.Hour + time.Second)
	if s2.check(code2) {
		t.Error("expired code passed")
	}
}

func TestSetupClaimIsSingleUse(t *testing.T) {
	s, code, _ := NewSetup(time.Now, time.Hour)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range 20 {
		wg.Go(func() {
			if s.Claim(code) {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d concurrent claims won, want exactly 1", wins)
	}
	s.Release()
	if !s.Claim(code) {
		t.Error("a released claim (failed account creation) cannot be retried")
	}
}

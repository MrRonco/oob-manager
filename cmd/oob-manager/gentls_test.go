package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenTLSWritesPairWithModes(t *testing.T) {
	dir := t.TempDir()
	rc, out, errOut := runCLI(t, "gen-tls", "--host", "192.0.2.20", "--host", "oob.example.test", "--out", dir)
	if rc != 0 {
		t.Fatalf("exit %d: %s", rc, errOut)
	}
	keyPath, certPath := filepath.Join(dir, "tls.key"), filepath.Join(dir, "tls.crt")
	for path, mode := range map[string]os.FileMode{keyPath: 0o600, certPath: 0o644} {
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != mode {
			t.Fatalf("%s: %v mode %v", path, err, st.Mode().Perm())
		}
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	files := os.DirFS(dir)
	b, _ := fs.ReadFile(files, "tls.crt")
	block, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(cert.NotAfter) > 825*24*time.Hour || len(cert.IPAddresses) != 1 || cert.DNSNames[0] != "oob.example.test" {
		t.Fatalf("cert %v %v %v", cert.NotAfter, cert.IPAddresses, cert.DNSNames)
	}
	key, _ := fs.ReadFile(files, "tls.key")
	if strings.Contains(out+errOut, string(key)) || !strings.Contains(out, "SHA-256 fingerprint") {
		t.Fatalf("output %q", out)
	}
	// Never overwrites.
	if rc, _, errOut := runCLI(t, "gen-tls", "--host", "192.0.2.20", "--out", dir); rc != 1 || !strings.Contains(errOut, "never overwritten") {
		t.Fatalf("overwrite: %d %q", rc, errOut)
	}
	if after, _ := fs.ReadFile(files, "tls.key"); string(after) != string(key) {
		t.Fatal("key replaced")
	}
}

func TestGenTLSErrors(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]struct {
		args []string
		want string
	}{
		"no host":   {[]string{"gen-tls", "--out", dir}, "--host and --out"},
		"no out":    {[]string{"gen-tls", "--host", "192.0.2.1"}, "--host and --out"},
		"bad host":  {[]string{"gen-tls", "--host", "not a host", "--out", dir}, "neither an IP"},
		"too long":  {[]string{"gen-tls", "--host", "x.test", "--out", dir, "--days", "826"}, "1-825"},
		"zero days": {[]string{"gen-tls", "--host", "x.test", "--out", dir, "--days", "0"}, "1-825"},
		"huge days": {[]string{"gen-tls", "--host", "x.test", "--out", dir, "--days", "9999999999999"}, "1-825"},
		"extra":     {[]string{"gen-tls", "--host", "x.test", "--out", dir, "junk"}, "expected 0"},
		"bad flag":  {[]string{"gen-tls", "--nope"}, "not defined"},
		"no dir":    {[]string{"gen-tls", "--host", "x.test", "--out", filepath.Join(dir, "missing")}, "no such file"},
	}
	for name, c := range cases {
		if rc, _, errOut := runCLI(t, c.args...); rc != 1 || !strings.Contains(errOut, c.want) {
			t.Errorf("%s: exit %d stderr %q", name, rc, errOut)
		}
	}
	// A failed certificate write removes the key it just wrote.
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc, _, _ := runCLI(t, "gen-tls", "--host", "x.test", "--out", dir); rc != 1 {
		t.Fatal("existing cert accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "tls.key")); !os.IsNotExist(err) {
		t.Fatalf("orphan key left behind: %v", err)
	}
}

func TestFingerprint(t *testing.T) {
	if got := fingerprint("0a1b2c"); got != "0A:1B:2C" {
		t.Fatal(got)
	}
}

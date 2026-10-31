package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// Generated at runtime; nothing secret is committed.
const plainPassword = "hunter2-correct-horse"

// opPassword is the second fixture password, outside the YAML literal so the scanner allow
// comment can sit on its line.
const opPassword = "other-pass-123" // gitleaks:allow (test fixture)

const credsYAML = `r730xd-ro:
  username: oob_ro
  password: ` + plainPassword + `
r730xd-op:
  username: oob_op
  password: ` + opPassword + `
`

type fixture struct {
	dir      string
	credPath string
	idPath   string
	identity *age.X25519Identity
}

func newFixture(t *testing.T, plaintext string) fixture {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f := fixture{dir: dir, credPath: filepath.Join(dir, "creds.age"), idPath: filepath.Join(dir, "identity"), identity: id}
	writeFile(t, f.idPath, []byte("# created: test\n"+id.String()+"\n"))
	writeFile(t, f.credPath, encrypt(t, id.Recipient(), plaintext))
	return f
}

func encrypt(t *testing.T, r age.Recipient, plaintext string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(plaintext)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadCredentials(t *testing.T) {
	f := newFixture(t, credsYAML)
	store, err := LoadCredentials(f.credPath, f.idPath)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	c, err := store.Lookup("r730xd-ro")
	if err != nil {
		t.Fatal(err)
	}
	if c.Username != "oob_ro" || c.Password.Reveal() != plainPassword {
		t.Errorf("got %q / wrong password", c.Username)
	}
	if _, err := store.Lookup("missing"); !errors.Is(err, ErrUnknownRef) {
		t.Errorf("missing ref err = %v", err)
	}
	if got := store.Refs(); len(got) != 2 || got[0] != "r730xd-op" {
		t.Errorf("Refs = %v", got)
	}
	if err := store.Require("r730xd-ro", "", "r730xd-op"); err != nil {
		t.Errorf("Require: %v", err)
	}
	if err := store.Require("r730xd-ro", "r240-ro"); err == nil || !strings.Contains(err.Error(), "r240-ro") {
		t.Errorf("Require missing: %v", err)
	}
}

func TestWrongKeyFails(t *testing.T) {
	f := newFixture(t, credsYAML)
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.idPath, []byte(other.String()+"\n"))
	if _, err := LoadCredentials(f.credPath, f.idPath); err == nil {
		t.Fatal("wrong identity accepted")
	}
}

func TestLoadFailures(t *testing.T) {
	f := newFixture(t, credsYAML)
	cases := map[string]func(t *testing.T) error{
		"missing identity": func(t *testing.T) error {
			_, err := LoadCredentials(f.credPath, filepath.Join(f.dir, "nope"))
			return err
		},
		"garbage identity": func(t *testing.T) error {
			p := filepath.Join(f.dir, "bad-id")
			writeFile(t, p, []byte("not a key\n"))
			_, err := LoadCredentials(f.credPath, p)
			return err
		},
		"missing creds": func(t *testing.T) error {
			_, err := LoadCredentials(filepath.Join(f.dir, "nope"), f.idPath)
			return err
		},
		"not age": func(t *testing.T) error {
			p := filepath.Join(f.dir, "plain")
			writeFile(t, p, []byte(credsYAML))
			_, err := LoadCredentials(p, f.idPath)
			return err
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			err := fn(t)
			if err == nil {
				t.Fatal("expected error")
			}
			if strings.Contains(err.Error(), plainPassword) {
				t.Error("error leaks secret")
			}
		})
	}
}

func TestParseCredentialsRejects(t *testing.T) {
	cases := map[string]string{ //nolint:gosec // G101: malformed credential-file test inputs, no real secret
		"empty":         "",
		"not yaml":      "a: [",
		"unknown field": "x:\n  username: u\n  password: p\n  token: t\n",
		"no password":   "x:\n  username: u\n",
		"bad ref":       "../x:\n  username: u\n  password: p\n",
		"two docs":      "x:\n  username: u\n  password: p\n---\ny: 1\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCredentials([]byte(src)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestDecryptSizeCap(t *testing.T) {
	f := newFixture(t, strings.Repeat("a", MaxPlaintextBytes+1))
	ids, err := LoadIdentities(f.idPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptFile(f.credPath, ids); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("err = %v", err)
	}
}

func TestDecryptFileGeneric(t *testing.T) {
	f := newFixture(t, "app-key-material")
	ids, err := LoadIdentities(f.idPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptFile(f.credPath, ids)
	if err != nil {
		t.Fatal(err)
	}
	if got.Reveal() != "app-key-material" {
		t.Error("wrong plaintext")
	}
	if _, err := DecryptFile(f.credPath, nil); err == nil {
		t.Error("no identities accepted")
	}
}

func TestSecretRedaction(t *testing.T) {
	s := New(plainPassword)
	type wrapper struct {
		User string
		Pass Secret
		Ptr  *Secret
	}
	w := wrapper{User: "u", Pass: s, Ptr: &s}
	outputs := []string{
		s.String(), s.GoString(),
		fmt.Sprintf("%v %+v %#v %s %q %x %X %d %10s", s, s, s, s, s, s, s, s, s),
		fmt.Sprintf("%v %+v %#v", w, w, w),
		fmt.Sprint(s), fmt.Sprintln(&s),
	}
	js, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	outputs = append(outputs, string(js))
	txt, err := s.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	outputs = append(outputs, string(txt))

	var logBuf bytes.Buffer
	lg := slog.New(slog.NewJSONHandler(&logBuf, nil))
	lg.Info("login", "password", s, "cred", Credential{Username: "svc", Password: s}, "w", w)
	lg2 := slog.New(slog.NewTextHandler(&logBuf, nil))
	lg2.Info("login", "password", s, "cred", Credential{Username: "svc", Password: s})
	outputs = append(outputs, logBuf.String())

	for i, out := range outputs {
		if strings.Contains(out, plainPassword) || strings.Contains(out, fmt.Sprintf("%x", plainPassword)) {
			t.Errorf("output %d leaks secret: %s", i, out)
		}
		if !strings.Contains(out, Redacted) {
			t.Errorf("output %d lacks marker: %s", i, out)
		}
	}
	if !strings.Contains(logBuf.String(), "svc") {
		t.Error("credential username should be logged")
	}
}

func TestSecretValueSemantics(t *testing.T) {
	a := New("abc")
	b := FromBytes([]byte("abc"))
	if !a.Equal(b) || a.Equal(New("abd")) || a.IsZero() || !(Secret{}).IsZero() {
		t.Error("Equal/IsZero wrong")
	}
	raw := a.Bytes()
	raw[0] = 'X'
	if a.Reveal() != "abc" {
		t.Error("Bytes() exposed internal storage")
	}
	src := []byte("xyz")
	c := FromBytes(src)
	src[0] = 'Q'
	if c.Reveal() != "xyz" {
		t.Error("FromBytes aliased input")
	}
	if (Secret{}).String() != Redacted {
		t.Error("zero secret should still redact")
	}
}

// A VNC entry carries only a password (RFB VNC authentication has no user name).
func TestParseCredentialsPasswordOnly(t *testing.T) {
	creds, err := ParseCredentials([]byte("r1-vnc:\n  password: Ab1!xyz9\nr1-ro:\n  username: u\n  password: p\n"))
	if err != nil {
		t.Fatal(err)
	}
	vnc, err := creds.Lookup("r1-vnc")
	if err != nil || vnc.Username != "" || vnc.Password.Reveal() != "Ab1!xyz9" || vnc.HasLogin() {
		t.Errorf("vnc entry = %+v, %v", vnc, err)
	}
	ro, _ := creds.Lookup("r1-ro")
	if !ro.HasLogin() {
		t.Error("username + password entry must report HasLogin")
	}
}

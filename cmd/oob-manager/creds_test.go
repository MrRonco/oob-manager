package main

import (
	"errors"
	"testing"

	"oob-manager/internal/config"
	"oob-manager/internal/secrets"
	"oob-manager/internal/secrets/credstore"
)

func TestCredSetKeepsSourcesApart(t *testing.T) {
	file, err := secrets.ParseCredentials([]byte("edge1-ro: {username: file, password: f}\n"))
	if err != nil {
		t.Fatal(err)
	}
	set := credSet{file: file, db: map[string]secrets.Credential{
		dbRef("edge1", credstore.SlotReadOnly): {Username: "db", Password: secrets.New("d")}}}
	if c, err := set.Lookup("edge1-ro"); err != nil || c.Username != "file" {
		t.Fatalf("file ref: %+v %v", c, err)
	}
	if c, err := set.Lookup("db/edge1/readonly"); err != nil || c.Username != "db" {
		t.Fatalf("db ref: %+v %v", c, err)
	}
	if _, err := set.Lookup("db/edge1/operator"); !errors.Is(err, errNoCredential) {
		t.Fatalf("missing db ref: %v", err)
	}
	s := withDBRefs(config.Server{ID: "edge1", Credentials: config.CredentialRef{ReadOnly: "readonly", VNC: "vnc"}})
	if s.Credentials.ReadOnly != "db/edge1/readonly" || s.Credentials.Operator != "" || s.Credentials.VNC != "db/edge1/vnc" {
		t.Fatalf("refs = %+v", s.Credentials)
	}
}

func TestTargetFingerprintIsStable(t *testing.T) {
	on := true
	a := config.Server{ID: "x", Console: config.ConsoleConfig{VNC: config.VNCConfig{TLS: &on}}}
	on2 := true
	b := config.Server{ID: "x", Console: config.ConsoleConfig{VNC: config.VNCConfig{TLS: &on2}}}
	login := secrets.Credential{Username: "u", Password: secrets.New("p")}
	if targetFingerprint(a, "e", login) != targetFingerprint(b, "e", login) {
		t.Fatal("equal configs (different pointers) gave different fingerprints")
	}
	other := secrets.Credential{Username: "u", Password: secrets.New("q")}
	if targetFingerprint(a, "e", login) == targetFingerprint(a, "e", other) ||
		targetFingerprint(a, "e", login) == targetFingerprint(a, "f", login) {
		t.Fatal("a new password or endpoint kept the fingerprint")
	}
}

func TestSelfAddrsIncludeInterfaces(t *testing.T) {
	got := selfAddrs(config.Config{Listen: "192.0.2.5:8443", PublicURL: "https://198.51.100.9:8443/"})
	has := func(s string) bool {
		for _, a := range got {
			if a.String() == s {
				return true
			}
		}
		return false
	}
	if !has("127.0.0.1") || !has("192.0.2.5") || !has("198.51.100.9") {
		t.Fatalf("self = %v", got)
	}
}

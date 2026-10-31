package secrets

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestLoadAppKeys(t *testing.T) {
	key := strings.Repeat("ab", 32)
	f := newFixture(t, "totp_key: "+key+"\n")
	ids, err := LoadIdentities(f.idPath)
	if err != nil {
		t.Fatal(err)
	}
	k, err := LoadAppKeys(f.credPath, ids)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString(key)
	if string(k.TOTPKey.Bytes()) != string(want) {
		t.Fatal("wrong key bytes")
	}
	if s := fmt.Sprintf("%v %+v", k, k); strings.Contains(s, "ab") {
		t.Fatalf("app keys leak through formatting: %s", s)
	}
}

func TestParseAppKeysRejects(t *testing.T) {
	for name, doc := range map[string]string{
		"empty":     "",
		"short":     "totp_key: abcd\n",
		"not hex":   "totp_key: " + strings.Repeat("zz", 32) + "\n",
		"unknown":   "totp_key: " + strings.Repeat("ab", 32) + "\nother: 1\n",
		"two docs":  "totp_key: " + strings.Repeat("ab", 32) + "\n---\ntotp_key: x\n",
		"not a map": "- a\n",
	} {
		_, err := ParseAppKeys([]byte(doc))
		if err == nil {
			t.Errorf("%s: want error", name)
			continue
		}
		if strings.Contains(err.Error(), "abab") || strings.Contains(err.Error(), "zz") {
			t.Errorf("%s: error leaks the value: %v", name, err)
		}
	}
}

func TestLoadAppKeysWrongIdentity(t *testing.T) {
	f := newFixture(t, "totp_key: "+strings.Repeat("ab", 32)+"\n")
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAppKeys(f.credPath, []age.Identity{other}); err == nil {
		t.Fatal("want decrypt failure")
	}
	if _, err := LoadAppKeys(filepath.Join(f.dir, "missing"), []age.Identity{other}); err == nil {
		t.Fatal("want missing-file failure")
	}
}

func TestGenerateAppKeys(t *testing.T) {
	doc, err := GenerateAppKeys()
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParseAppKeys(doc)
	if err != nil || len(k.TOTPKey.Bytes()) != AppKeyBytes {
		t.Fatalf("generated document does not parse: %v", err)
	}
	other, _ := GenerateAppKeys()
	if string(other) == string(doc) {
		t.Fatal("keys must be random")
	}
}

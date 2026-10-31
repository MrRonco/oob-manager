package secrets

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	k := AppKeys{TOTPKey: FromBytes(bytes.Repeat([]byte{7}, AppKeyBytes))}
	a, err := k.DeriveKey(PurposeCSRF)
	if err != nil || len(a) != AppKeyBytes {
		t.Fatalf("derive: %d %v", len(a), err)
	}
	again, _ := k.DeriveKey(PurposeCSRF)
	if !bytes.Equal(a, again) {
		t.Fatal("derivation is not deterministic")
	}
	if bytes.Equal(a, k.TOTPKey.Bytes()) {
		t.Fatal("derived key equals the TOTP key")
	}
	other, _ := AppKeys{TOTPKey: FromBytes(bytes.Repeat([]byte{8}, AppKeyBytes))}.DeriveKey(PurposeCSRF)
	if bytes.Equal(a, other) {
		t.Fatal("different master keys gave the same derived key")
	}
}

func TestDeriveKeyRejects(t *testing.T) {
	if _, err := (AppKeys{}).DeriveKey(PurposeCSRF); err == nil {
		t.Fatal("empty master key accepted")
	}
	k := AppKeys{TOTPKey: FromBytes(bytes.Repeat([]byte{7}, AppKeyBytes))}
	if _, err := k.DeriveKey(""); err == nil || strings.Contains(err.Error(), "07") {
		t.Fatalf("empty purpose: %v", err)
	}
}

func TestPurposesAreIndependent(t *testing.T) {
	k := AppKeys{TOTPKey: FromBytes(bytes.Repeat([]byte{7}, AppKeyBytes))}
	seen := map[string]string{}
	for _, p := range []string{PurposeCSRF, PurposeBMCCred, PurposeTOFU, PurposeNotify} {
		d, err := k.DeriveKey(p)
		if err != nil {
			t.Fatal(err)
		}
		if prev, dup := seen[string(d)]; dup {
			t.Fatalf("%s and %s derive the same key", p, prev)
		}
		seen[string(d)] = p
	}
}

// TestPurposeLabelsArePinned freezes the HKDF labels and the keys they derive. The labels
// keep the pre-rename project name (oob-console) on purpose: a new label derives a new
// key, which would orphan every sealed BMC credential and notification secret, break
// every TOFU pin proof and invalidate open forms on an existing install.
func TestPurposeLabelsArePinned(t *testing.T) {
	k := AppKeys{TOTPKey: FromBytes(bytes.Repeat([]byte{7}, AppKeyBytes))}
	for _, c := range []struct{ got, label, key string }{
		{PurposeCSRF, "oob-console/csrf/v1", "755d71f6d9d26bdc65fcd96945266ec703fa534f2fd5d055b1d4cafa07aeded6"},
		{PurposeBMCCred, "oob-console/bmc-cred/v1", "4847d59971e0c83cfd000a5fb684b1fb852067ff48be31510be1518907812bdb"},
		{PurposeTOFU, "oob-console/tofu/v1", "d5253ada0ce15aaf798df76ce8ddb38cbe99aaa55ea0b9a890d1a8804dbc9a8f"},
		{PurposeNotify, "oob-console/notify/v1", "033f9dc454d969d712ca287987a2d6d8f99165f87abe39a32c7e5efa3ece7a47"},
	} {
		if c.got != c.label {
			t.Errorf("purpose label changed: %q, want %q", c.got, c.label)
		}
		d, err := k.DeriveKey(c.label)
		if err != nil || hex.EncodeToString(d) != c.key {
			t.Errorf("%s derives %x (%v), want %s", c.label, d, err, c.key)
		}
	}
}

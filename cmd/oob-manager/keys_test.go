package main

import (
	"bytes"
	"testing"

	"oob-manager/internal/notify"
	"oob-manager/internal/secrets"
	"oob-manager/internal/secrets/credstore"
)

// TestSealedSecretKeysAreSeparate: browser-saved BMC credentials (S3) and notification
// target secrets each use their own HKDF purpose, so the four derived keys (CSRF, BMC
// credentials, TOFU proofs, notifications) are pairwise different and none is the master.
func TestSealedSecretKeysAreSeparate(t *testing.T) {
	master := bytes.Repeat([]byte{9}, secrets.AppKeyBytes)
	c := &core{}
	if err := c.deriveKeys(secrets.AppKeys{TOTPKey: secrets.FromBytes(master)}); err != nil {
		t.Fatal(err)
	}
	keys := map[string][]byte{"csrf": c.csrfKey, "bmc-cred": c.credKey, "tofu": c.tofuKey, "notify": c.notifyKey}
	seen := map[string]string{}
	for name, k := range keys {
		if len(k) != 32 || bytes.Equal(k, master) {
			t.Fatalf("%s key: len %d, equals master %v", name, len(k), bytes.Equal(k, master))
		}
		if prev, dup := seen[string(k)]; dup {
			t.Fatalf("%s and %s share a key", name, prev)
		}
		seen[string(k)] = name
	}
	if notify.PurposeNotify != secrets.PurposeNotify || secrets.PurposeNotify == secrets.PurposeBMCCred {
		t.Fatal("notification purpose is not the one defined with the other labels")
	}
}

// TestSealedSecretDomainsDoNotCross: even under one key, a notification blob never opens
// as a BMC credential, because the additional data carries a different domain prefix
// (notify/v1|… vs bmc-cred/v1|…).
func TestSealedSecretDomainsDoNotCross(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	ns, err := notify.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := credstore.New(key)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := ns.Seal(notify.Target{ID: "r650", Kind: notify.KindWebhook, URL: "https://192.0.2.1/h"},
		notify.Secrets{Token: secrets.New("hmac-key")})
	if err != nil {
		t.Fatal(err)
	}
	b := credstore.Binding{ServerID: "r650", Slot: credstore.SlotReadOnly, Kind: "idrac9", Address: "192.0.2.1",
		Port: 443, Version: 1}
	if _, err = cs.Open(b, blob); err == nil {
		t.Fatal("a notification blob opened as a BMC credential")
	}
	cblob, err := cs.Seal(b, secrets.Credential{Username: "ro", Password: secrets.New("pw")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ns.Open(notify.Target{ID: "r650", Kind: notify.KindWebhook, URL: "https://192.0.2.1/h"}, cblob); err == nil {
		t.Fatal("a BMC credential opened as notification secrets")
	}
}

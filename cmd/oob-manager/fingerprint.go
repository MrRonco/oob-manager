package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"oob-manager/internal/config"
	"oob-manager/internal/secrets"
)

// fingerprint identifies everything a server's driver or applier is built from: the
// server's whole (normalised) config, the endpoint, the login and any extra value. It
// is compared in memory only (fleet.Apply, fan.SetTargets) to keep a running poller or
// applier whose inputs did not change; it is never logged or stored.
func targetFingerprint(s config.Server, endpoint string, login secrets.Credential, extra ...string) string {
	h := sha256.New()
	doc, _ := json.Marshal(s) // values, not pointers: equal configs give equal bytes
	h.Write(doc)
	_, _ = fmt.Fprintf(h, "|%s|%s|", endpoint, login.Username)
	h.Write(login.Password.Bytes())
	for _, x := range extra {
		_, _ = fmt.Fprintf(h, "|%s", x)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// loginOf looks up ref, or returns a zero credential.
func loginOf(creds credLookup, ref string) secrets.Credential {
	if ref == "" {
		return secrets.Credential{}
	}
	c, err := creds.Lookup(ref)
	if err != nil {
		return secrets.Credential{}
	}
	return c
}

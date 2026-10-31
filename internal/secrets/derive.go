package secrets

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
)

// Purposes for DeriveKey. Each label yields an independent key (HKDF domain separation),
// so new uses never need a new field in the app-keys file.
//
// The labels keep the project's pre-rename name (oob-console) ON PURPOSE and must never
// change: the label is an HKDF input, so a new one derives a new key and an existing
// install would lose every sealed credential and notification secret, every TOFU pin
// proof and every open form (TestPurposeLabelsArePinned). A new purpose may use any
// label; existing ones stay as they are.
const (
	// PurposeCSRF keys the UI's form-token HMAC. Stable across restarts, so open
	// forms survive a redeploy.
	PurposeCSRF = "oob-console/csrf/v1"
	// PurposeBMCCred keys the AES-256-GCM sealing of BMC credentials saved from the
	// browser (internal/secrets/credstore).
	PurposeBMCCred = "oob-console/bmc-cred/v1" //nolint:gosec // G101: an HKDF label, not a credential
	// PurposeTOFU keys the HMAC that proves a pinned fingerprint is the one the app
	// fetched (internal/tofu).
	PurposeTOFU = "oob-console/tofu/v1"
	// PurposeNotify keys the AES-256-GCM sealing of notification target secrets saved
	// from the browser (internal/notify). Separate from PurposeBMCCred: a target secret
	// and a BMC credential never share a key, and their AADs differ too.
	PurposeNotify = "oob-console/notify/v1"
)

// DeriveKey returns a 32-byte subkey of the app-keys master (the TOTP key) for one
// purpose, via HKDF-SHA256. The TOTP key itself is never used for anything else.
func (k AppKeys) DeriveKey(purpose string) ([]byte, error) {
	if purpose == "" {
		return nil, errors.New("secrets: derive: purpose is required")
	}
	master := k.TOTPKey.Bytes()
	defer wipe(master)
	if len(master) != AppKeyBytes {
		return nil, errors.New("secrets: derive: app keys are not loaded")
	}
	return hkdf.Key(sha256.New, master, nil, purpose, AppKeyBytes)
}

package rfb

import (
	"encoding/hex"
	"testing"
)

// Vectors computed with noVNC 1.7.0's own DES implementation (core/crypto/des.js,
// RFB.genDES), an independent code base, for the challenge 00 01 02 … 0f.
func TestVNCAuthResponseMatchesNoVNC(t *testing.T) {
	var ch [16]byte
	for i := range ch {
		ch[i] = byte(i)
	}
	cases := map[string]string{ //nolint:gosec // G101: public test vectors, not credentials
		"password":       "b866924125c8eebb9debc1db61c538e2",
		"Ab1!xyz9LONGER": "1a34cfb958d908a0e1d87743e2bf660b", // only the first 8 bytes count
		"abc":            "9c22b4f2088c3465a1562c4b9d6edb04", // zero padded
	}
	for pw, want := range cases {
		got := VNCAuthResponse(ch, []byte(pw))
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("%q: got %x, want %s", pw, got, want)
		}
	}
	if VNCAuthResponse(ch, []byte("Ab1!xyz9")) != VNCAuthResponse(ch, []byte("Ab1!xyz9-ignored")) {
		t.Error("bytes after the eighth must be ignored")
	}
}

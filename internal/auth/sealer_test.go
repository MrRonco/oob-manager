package auth

import (
	"bytes"
	"testing"
)

func TestAESGCMSealer(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	s, err := NewAESGCMSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	key[0] = 0 // caller mutating its slice must not affect the sealer
	ct, err := s.Seal([]byte("JBSWY3DPEHPK3PXP"), []byte("user-1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("JBSWY3DPEHPK3PXP")) {
		t.Fatal("plaintext visible in ciphertext")
	}
	pt, err := s.Open(ct, []byte("user-1"))
	if err != nil || string(pt) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("Open = %q, %v", pt, err)
	}
	if _, err := s.Open(ct, []byte("user-2")); err == nil {
		t.Fatal("ciphertext opened under another user's AAD")
	}
	ct[len(ct)-1] ^= 1
	if _, err := s.Open(ct, []byte("user-1")); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
	if _, err := s.Open([]byte{1, 2}, nil); err == nil {
		t.Fatal("short ciphertext opened")
	}
}

func TestAESGCMSealerKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 24, 31, 33} {
		if _, err := NewAESGCMSealer(make([]byte, n)); err == nil {
			t.Errorf("key length %d accepted", n)
		}
	}
}

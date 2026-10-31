package dell

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/firmware/catalog/catalogtest"
)

func TestEmbeddedKeyIsPinned(t *testing.T) {
	k, err := LoadKeys(nil)
	if err != nil {
		t.Fatal(err)
	}
	if fps := k.Fingerprints(); len(fps) != 1 || fps[0] != DellFingerprint {
		t.Fatalf("fingerprints %v", fps)
	}
	saved := dellKey
	t.Cleanup(func() { dellKey = saved })
	dellKey = catalogtest.NewRSAKey(t).PublicArmored(t)
	if _, err := LoadKeys(nil); err == nil {
		t.Fatal("a different embedded key was accepted")
	}
}

func TestVerifyV4(t *testing.T) {
	key := catalogtest.RSAKey(t)
	data := catalogtest.Catalog()
	k, err := LoadKeys(key.PublicArmored(t))
	if err != nil {
		t.Fatal(err)
	}
	sig := key.Sign(t, data)
	s, err := k.Verify(bytes.NewReader(data), sig)
	if err != nil || s.Fingerprint != key.Fingerprint() || s.Legacy || len(s.KeyID) != 16 {
		t.Fatalf("good signature: %+v %v", s, err)
	}
	flipped := bytes.Clone(data)
	flipped[len(flipped)/2] ^= 1
	if _, err = k.Verify(bytes.NewReader(flipped), sig); !errors.Is(err, catalog.ErrSignature) {
		t.Errorf("one bit flipped: %v", err)
	}
	other := catalogtest.NewRSAKey(t)
	err = verifyErr(k, data, other.Sign(t, data))
	if !errors.Is(err, catalog.ErrUntrustedKey) || catalog.Class(err) != "untrusted_key" || !strings.Contains(err.Error(), "key ID") {
		t.Errorf("unknown key: %v", err)
	}
	if err := verifyErr(k, data, key.SignSHA1(t, data)); !errors.Is(err, catalog.ErrSignature) {
		t.Errorf("SHA-1 from a non-legacy key: %v", err)
	}
	if extra, err := LoadKeys([]byte("not a key")); err == nil {
		t.Errorf("bad extra keys loaded: %v", extra.Fingerprints())
	}
}

func TestVerifyRefusesMalformedSignatures(t *testing.T) {
	key := catalogtest.RSAKey(t)
	data := catalogtest.Catalog()
	k, _ := LoadKeys(key.PublicArmored(t))
	raw := catalogtest.Dearmor(t, key.Sign(t, data))
	cases := map[string][]byte{
		"oversized":       bytes.Repeat([]byte("A"), MaxSignatureBytes+1),
		"not armor":       []byte("hello"),
		"two packets":     catalogtest.ArmorPackets(t, append(bytes.Clone(raw), raw...)),
		"empty armor":     catalogtest.ArmorPackets(t, nil),
		"a key, not sig":  catalogtest.ArmorPackets(t, catalogtest.Dearmor(t, bytes.Replace(key.PublicArmored(t), []byte("PUBLIC KEY BLOCK"), []byte("SIGNATURE"), 2))),
		"public key type": key.PublicArmored(t),
	}
	for name, sig := range cases {
		if err := verifyErr(k, data, sig); !errors.Is(err, catalog.ErrSignature) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestVerifyLegacyV3DSA(t *testing.T) {
	key := catalogtest.DSAKey(t)
	data := catalogtest.Catalog()
	sig := key.Sign(t, data)
	// As an extra (non-legacy) key, SHA-1 is refused.
	k, err := LoadKeys(key.PublicArmored(t))
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyErr(k, data, sig); !errors.Is(err, catalog.ErrSignature) {
		t.Fatalf("v3 SHA-1 from a non-legacy key: %v", err)
	}
	// Pinned as legacy (Dell's case), it verifies, and a flipped bit fails.
	k, _ = LoadKeys(nil)
	ring, err := primaryKeys(key.PublicArmored(t))
	if err != nil {
		t.Fatal(err)
	}
	if err = k.add(ring[0], true); err != nil {
		t.Fatal(err)
	}
	s, err := k.Verify(bytes.NewReader(data), sig)
	if err != nil || !s.Legacy || s.Fingerprint != key.Fingerprint() {
		t.Fatalf("legacy v3: %+v %v", s, err)
	}
	flipped := bytes.Clone(data)
	flipped[10] ^= 1
	if err := verifyErr(k, flipped, sig); !errors.Is(err, catalog.ErrSignature) {
		t.Errorf("legacy v3 over changed data: %v", err)
	}
}

func verifyErr(k Keys, data, sig []byte) error {
	_, err := k.Verify(bytes.NewReader(data), sig)
	return err
}

func FuzzVerifyArmored(f *testing.F) {
	k, err := LoadKeys(nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte("-----BEGIN PGP SIGNATURE-----\n\niQA=\n=AAAA\n-----END PGP SIGNATURE-----\n"))
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, sig []byte) {
		if _, err := k.Verify(bytes.NewReader([]byte("data")), sig); err == nil {
			t.Fatal("a fuzzed signature verified")
		}
	})
}

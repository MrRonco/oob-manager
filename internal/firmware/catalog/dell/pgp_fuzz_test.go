package dell

import (
	"bytes"
	"testing"

	"oob-manager/internal/firmware/catalog/catalogtest"
)

// FuzzPGPVerify: a real signature over fixed data, with the data and the signature both
// mutated. Changed data must never verify, whatever happened to the signature, and no
// input panics. (A changed signature may still verify when only bytes the signature
// does not cover moved, such as armor whitespace, so that is not asserted.)
func FuzzPGPVerify(f *testing.F) {
	key := catalogtest.RSAKey(f)
	k, err := LoadKeys(key.PublicArmored(f))
	if err != nil {
		f.Fatal(err)
	}
	data := catalogtest.Catalog()
	sig := key.Sign(f, data)
	f.Add(uint32(0), byte(0), uint32(0), byte(0))
	f.Add(uint32(10), byte(1), uint32(0), byte(0))
	f.Add(uint32(0), byte(0), uint32(60), byte(0x20))
	f.Add(uint32(0xFFFFFFFF), byte(0x80), uint32(0x7FFFFFFF), byte(4)) // indexes wrap modulo the length
	f.Fuzz(func(t *testing.T, di uint32, dmask byte, si uint32, smask byte) {
		d, s := bytes.Clone(data), bytes.Clone(sig)
		d[int(di)%len(d)] ^= dmask
		s[int(si)%len(s)] ^= smask
		if _, err := k.Verify(bytes.NewReader(d), s); err == nil && !bytes.Equal(d, data) {
			t.Fatalf("changed data verified (byte %d ^ %#x)", int(di)%len(d), dmask)
		}
	})
}

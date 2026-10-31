package dell

import (
	"bytes"
	"crypto/dsa" //nolint:staticcheck // SA1019: the DSA sanity checks under test
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/firmware/catalog/catalogtest"
)

func trusting(t *testing.T, key catalogtest.Key) Keys {
	t.Helper()
	k, err := LoadKeys(key.PublicArmored(t))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestVerifyRSALeadingZero(t *testing.T) {
	key := catalogtest.RSAKey(t)
	k := trusting(t, key)
	data := []byte("catalog bytes")
	sig := key.SignCustom(t, data, catalogtest.SigOpts{LeadingZero: true})
	if _, err := k.Verify(bytes.NewReader(data), sig); err != nil {
		t.Fatalf("a valid signature with a leading zero byte was refused: %v", err)
	}
}

func TestVerifyIssuerAndSubpackets(t *testing.T) {
	key, other := catalogtest.RSAKey(t), catalogtest.NewRSAKey(t)
	k := trusting(t, key)
	data := []byte("catalog bytes")
	otherID := catalogtest.Subpacket(16, other.KeyID())
	expires := func(sec uint32) []byte { return catalogtest.Subpacket(3, binary.BigEndian.AppendUint32(nil, sec)) }
	cases := map[string]struct {
		o    catalogtest.SigOpts
		want error
	}{
		"unhashed issuer cannot override the hashed one": {catalogtest.SigOpts{Unhashed: [][]byte{otherID}}, nil},
		"hashed key ID and fingerprint disagree":         {catalogtest.SigOpts{ExtraHashed: [][]byte{otherID}}, catalog.ErrSignature},
		"only an unhashed issuer":                        {catalogtest.SigOpts{OmitIssuerFP: true}, nil},
		"no issuer at all":                               {catalogtest.SigOpts{OmitIssuerFP: true, Unhashed: [][]byte{}}, catalog.ErrSignature},
		"unknown critical hashed subpacket":              {catalogtest.SigOpts{ExtraHashed: [][]byte{{2, 0x80 | 99, 0}}}, catalog.ErrSignature},
		"unknown non-critical subpacket":                 {catalogtest.SigOpts{ExtraHashed: [][]byte{{2, 99, 0}}}, nil},
		"not over binary data":                           {catalogtest.SigOpts{SigType: 0x01}, catalog.ErrSignature},
		"expired":                                        {catalogtest.SigOpts{ExtraHashed: [][]byte{expires(1)}}, catalog.ErrSignature},
		"not yet expired":                                {catalogtest.SigOpts{ExtraHashed: [][]byte{expires(3600)}}, nil},
	}
	for name, c := range cases {
		sig := key.SignCustom(t, data, c.o)
		_, err := k.verifyAt(bytes.NewReader(data), sig, time.Now().Add(10*time.Second))
		if (c.want == nil) != (err == nil) || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A hashed fingerprint names the key exactly: a key with the same key ID but another
	// fingerprint does not verify.
	ps, err := packets(catalogtest.Dearmor(t, key.SignCustom(t, data, catalogtest.SigOpts{})))
	if err != nil || len(ps) != 1 {
		t.Fatal(err)
	}
	s, err := parseSignature(ps[0].body)
	if err != nil || s.issuerFP != key.Fingerprint() {
		t.Fatalf("fingerprint %q %v", s.issuerFP, err)
	}
	pk := k.byID[s.issuer]
	pk.fingerprint = strings.Repeat("0", 40)
	if s.verify(pk, make([]byte, 32)) {
		t.Fatal("a mismatching fingerprint verified")
	}
}

func TestArmorAndPacketEdges(t *testing.T) {
	key := catalogtest.RSAKey(t)
	k := trusting(t, key)
	data := []byte("catalog bytes")
	sig := string(key.Sign(t, data))
	badCRC := strings.Replace(sig, "\n=", "\n=AAAA", 1)
	badCRC = badCRC[:strings.Index(badCRC, "=AAAA")+5] + badCRC[strings.Index(badCRC, "\n-----END"):]
	bareEq := badCRC[:strings.Index(badCRC, "=AAAA")+1] + badCRC[strings.Index(badCRC, "=AAAA")+5:]
	noCRC := badCRC[:strings.Index(badCRC, "=AAAA")] + badCRC[strings.Index(badCRC, "=AAAA")+6:]
	for name, s := range map[string]string{"crc mismatch": badCRC, "bare =": bareEq} {
		if _, err := k.Verify(bytes.NewReader(data), []byte(s)); !errors.Is(err, catalog.ErrSignature) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := k.Verify(bytes.NewReader(data), []byte("junk before\n"+noCRC+"junk after\n")); err != nil {
		t.Errorf("no CRC, text around the block: %v", err)
	}
	// Old-format packets with two- and four-octet lengths.
	body := []byte{1, 2, 3}
	for _, raw := range [][]byte{
		append([]byte{0x80 | 2<<2 | 1, 0, 3}, body...),
		append([]byte{0x80 | 2<<2 | 2, 0, 0, 0, 3}, body...),
	} {
		ps, err := packets(raw)
		if err != nil || len(ps) != 1 || !bytes.Equal(ps[0].body, body) {
			t.Errorf("% x: %v %v", raw[:3], ps, err)
		}
	}
	for _, raw := range [][]byte{{0x80 | 2<<2 | 3, 0}, {0xC2, 230}, {0xC2, 5, 1}, {0x02, 1, 1}} {
		if _, err := packets(raw); err == nil {
			t.Errorf("% x parsed", raw)
		}
	}
	if _, _, err := mpi([]byte{0, 16, 1}); err == nil {
		t.Error("a truncated MPI parsed")
	}
	if _, err := parseSignature([]byte{5}); err == nil {
		t.Error("signature version 5 parsed")
	}
}

func TestKeySanity(t *testing.T) {
	dk := catalogtest.DSAKey(t)
	if _, err := LoadKeys(dk.PublicArmored(t)); err != nil {
		t.Fatalf("a sane DSA key refused: %v", err)
	}
	priv := dk.DSAPublic()
	small := *priv
	small.Q = big.NewInt(101)
	badG := *priv
	badG.G = big.NewInt(1)
	for name, pk := range map[string]*dsa.PublicKey{"small q": &small, "g = 1": &badG} {
		if saneDSA(pk) {
			t.Errorf("%s accepted", name)
		}
	}
	// Two different keys with one key ID are refused.
	var k Keys
	k.byID, k.legacy = map[uint64]pubKey{}, map[uint64]bool{}
	if err := k.add(pubKey{keyID: 7, fingerprint: "A"}, false); err != nil {
		t.Fatal(err)
	}
	if err := k.add(pubKey{keyID: 7, fingerprint: "A"}, false); err != nil || len(k.Fingerprints()) != 1 {
		t.Fatalf("the same key twice: %v", err)
	}
	if err := k.add(pubKey{keyID: 7, fingerprint: "B"}, false); err == nil {
		t.Fatal("a key ID collision was accepted")
	}
	// RSA: an even exponent is refused.
	if _, err := parsePublicKey(append([]byte{4, 0, 0, 0, 0, 1}, rsaMaterial(2048, 4)...)); err == nil {
		t.Fatal("an even RSA exponent was accepted")
	}
}

func rsaMaterial(bits int, e int64) []byte {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1)) //nolint:gosec // G115: test constant
	n.SetBit(n, 0, 1)
	out := binary.BigEndian.AppendUint16(nil, uint16(n.BitLen())) //nolint:gosec // G115: test constant
	out = append(out, n.Bytes()...)
	out = binary.BigEndian.AppendUint16(out, uint16(big.NewInt(e).BitLen())) //nolint:gosec // G115: test constant
	return append(out, big.NewInt(e).Bytes()...)
}

func FuzzParsePackets(f *testing.F) {
	key := catalogtest.RSAKey(f)
	f.Add(catalogtest.Dearmor(f, key.Sign(f, []byte("x"))))
	f.Add(catalogtest.Dearmor(f, key.PublicArmored(f)))
	f.Fuzz(func(_ *testing.T, b []byte) {
		ps, err := packets(b)
		if err != nil {
			return
		}
		for _, p := range ps {
			_, _ = parseSignature(p.body)
			_, _ = parsePublicKey(p.body)
		}
		_, _ = dearmor(b, armorSignature)
	})
}

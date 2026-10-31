package catalogtest

import (
	"crypto"
	"crypto/dsa" //nolint:staticcheck // SA1019: Dell signs with DSA; the legacy path is tested offline
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // G505: v4 fingerprints and Dell's v3 signatures are SHA-1
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// Key is a test OpenPGP signing key (a v4 primary key), built with the standard library
// only, like the verifier (RFC 4880).
type Key struct {
	rsa     *rsa.PrivateKey
	dsa     *dsa.PrivateKey
	created uint32
	body    []byte // the v4 public key packet body
}

var (
	rsaOnce sync.Once
	rsaKey  Key
	dsaOnce sync.Once
	dsaKey  Key
)

// RSAKey is a 2048-bit RSA test key (shared per test binary; generation is slow).
func RSAKey(t testing.TB) Key {
	t.Helper()
	rsaOnce.Do(func() { rsaKey = newRSA() })
	return rsaKey
}

// NewRSAKey is a fresh RSA key (for the "untrusted key" cases).
func NewRSAKey(t testing.TB) Key {
	t.Helper()
	return newRSA()
}

func newRSA() Key {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	k := Key{rsa: priv, created: now32()}
	k.body = keyBody(k.created, 1, mpis(priv.N, big.NewInt(int64(priv.E))))
	return k
}

// DSAKey is a DSA-1024 test key that makes v3 SHA-1 signatures, the shape Dell uses.
func DSAKey(t testing.TB) Key {
	t.Helper()
	dsaOnce.Do(func() {
		priv := new(dsa.PrivateKey)
		if err := dsa.GenerateParameters(&priv.Parameters, rand.Reader, dsa.L1024N160); err != nil {
			panic(err)
		}
		if err := dsa.GenerateKey(priv, rand.Reader); err != nil {
			panic(err)
		}
		dsaKey = Key{dsa: priv, created: now32()}
		dsaKey.body = keyBody(dsaKey.created, 17, mpis(priv.P, priv.Q, priv.G, priv.Y))
	})
	return dsaKey
}

func now32() uint32 { return uint32(time.Now().Unix()) } //nolint:gosec // G115: fits until 2106

func keyBody(created uint32, algo byte, material []byte) []byte {
	b := append(be32([]byte{4}, created), algo)
	return append(b, material...)
}

func mpis(ns ...*big.Int) []byte {
	var b []byte
	for _, n := range ns {
		b = binary.BigEndian.AppendUint16(b, uint16(n.BitLen())) //nolint:gosec // G115: test keys are < 2^16 bits
		b = append(b, n.Bytes()...)
	}
	return b
}

// DSAPublic is the DSA key's public half (nil for an RSA key).
func (k Key) DSAPublic() *dsa.PublicKey {
	if k.dsa == nil {
		return nil
	}
	pub := k.dsa.PublicKey
	return &pub
}

// Fingerprint is the key's upper-case hex v4 fingerprint.
func (k Key) Fingerprint() string { return fmt.Sprintf("%X", k.fp()) }

func (k Key) fp() []byte {
	h := sha1.New() //nolint:gosec // G401: the v4 fingerprint is SHA-1 by definition
	h.Write(be16([]byte{0x99}, len(k.body)))
	h.Write(k.body)
	return h.Sum(nil)
}

func (k Key) keyID() []byte { return k.fp()[12:20] }

// PublicArmored is the armored public key: the key packet and a user ID packet (no
// self-signature: the verifier trusts a key file as given).
func (k Key) PublicArmored(t testing.TB) []byte {
	t.Helper()
	uid := []byte("Catalog Test <catalog-test@example.com>")
	return Armor("PGP PUBLIC KEY BLOCK", append(Packet(6, k.body), Packet(13, uid)...))
}

// Sign returns an armored detached signature over data: v4 with SHA-256 for an RSA key,
// v3 with SHA-1 for the DSA key.
func (k Key) Sign(t testing.TB, data []byte) []byte {
	t.Helper()
	if k.dsa != nil {
		return k.signV3(t, data)
	}
	return Armor("PGP SIGNATURE", Packet(2, k.signV4(t, data, crypto.SHA256, 8)))
}

// SignSHA1 is a v4 SHA-1 signature (refused unless the key is a legacy one).
func (k Key) SignSHA1(t testing.TB, data []byte) []byte {
	t.Helper()
	return Armor("PGP SIGNATURE", Packet(2, k.signV4(t, data, crypto.SHA1, 2)))
}

// SigOpts shapes a custom v4 RSA/SHA-256 signature for the verifier's edge cases.
type SigOpts struct {
	SigType      byte     // 0x00 binary (default), anything else for the type check
	ExtraHashed  [][]byte // raw subpackets added to the hashed area
	Unhashed     [][]byte // raw unhashed subpackets (default: the issuer key ID)
	LeadingZero  bool     // retry until the RSA value starts with a zero byte
	OmitIssuerFP bool     // no hashed issuer fingerprint
}

// SignCustom returns an armored v4 signature shaped by o.
func (k Key) SignCustom(t testing.TB, data []byte, o SigOpts) []byte {
	t.Helper()
	for i := range 4096 {
		oi := o
		if o.LeadingZero { // PKCS#1 v1.5 is deterministic: vary a private-use subpacket
			oi.ExtraHashed = append(append([][]byte(nil), o.ExtraHashed...), Subpacket(101, binary.BigEndian.AppendUint32(nil, uint32(i)))) //nolint:gosec // G115: i < 4096
		}
		body, lead := k.signV4Opts(t, data, oi)
		if !o.LeadingZero || lead {
			return Armor("PGP SIGNATURE", Packet(2, body))
		}
	}
	t.Fatal("no signature with a leading zero byte in 4096 tries")
	return nil
}

// Subpacket builds one signature subpacket (one-octet length).
func Subpacket(typ byte, data []byte) []byte {
	return append([]byte{byte((len(data) + 1) & 0xFF), typ}, data...) // test subpackets are < 192 bytes
}

// KeyID is the key's 8-byte key ID.
func (k Key) KeyID() []byte { return k.keyID() }

// FingerprintBytes is the key's 20-byte fingerprint.
func (k Key) FingerprintBytes() []byte { return k.fp() }

func (k Key) signV4Opts(t testing.TB, data []byte, o SigOpts) ([]byte, bool) {
	t.Helper()
	created := now32()
	hashed := be32([]byte{5, 2}, created)
	if !o.OmitIssuerFP {
		hashed = append(append(hashed, 22, 33, 4), k.fp()...)
	}
	for _, sp := range o.ExtraHashed {
		hashed = append(hashed, sp...)
	}
	head := append(be16([]byte{4, o.SigType, 1, 8}, len(hashed)), hashed...)
	hh := sha256.New()
	hh.Write(data)
	hh.Write(head)
	hh.Write(be32([]byte{0x04, 0xFF}, uint32(len(head)))) //nolint:gosec // G115: a few hundred bytes
	digest := hh.Sum(nil)
	s, err := rsa.SignPKCS1v15(rand.Reader, k.rsa, crypto.SHA256, digest)
	if err != nil {
		t.Fatal(err)
	}
	unhashed := o.Unhashed
	if unhashed == nil {
		unhashed = [][]byte{Subpacket(16, k.keyID())}
	}
	var u []byte
	for _, sp := range unhashed {
		u = append(u, sp...)
	}
	out := append(be16(head, len(u)), u...)
	out = append(out, digest[0], digest[1])
	return append(out, mpis(new(big.Int).SetBytes(s))...), s[0] == 0
}

// SignV4Packet returns the raw v4 signature packet body (for malformed cases).
func (k Key) SignV4Packet(t testing.TB, data []byte) []byte {
	t.Helper()
	return Packet(2, k.signV4(t, data, crypto.SHA256, 8))
}

// signV4 builds a v4 RSA signature: version 4, type 0x00, algorithm 1, the hash, a hashed
// creation time and issuer fingerprint, an unhashed issuer key ID.
func (k Key) signV4(t testing.TB, data []byte, h crypto.Hash, hashID byte) []byte {
	t.Helper()
	created := now32()
	hashed := be32([]byte{5, 2}, created)
	hashed = append(append(hashed, 22, 33, 4), k.fp()...)
	head := append(be16([]byte{4, 0x00, 1, hashID}, len(hashed)), hashed...)
	hh := h.New()
	hh.Write(data)
	hh.Write(head)
	n := len(head)
	hh.Write(be32([]byte{0x04, 0xFF}, uint32(n))) //nolint:gosec // G115: a few hundred bytes
	digest := hh.Sum(nil)
	s, err := rsa.SignPKCS1v15(rand.Reader, k.rsa, h, digest)
	if err != nil {
		t.Fatal(err)
	}
	unhashed := append([]byte{9, 16}, k.keyID()...)
	out := append(be16(head, len(unhashed)), unhashed...)
	out = append(out, digest[0], digest[1])
	return append(out, mpis(new(big.Int).SetBytes(s))...)
}

// signV3 builds a version 3 DSA/SHA-1 signature packet, the format Dell publishes.
func (k Key) signV3(t testing.TB, data []byte) []byte {
	t.Helper()
	created := now32()
	h := sha1.New() //nolint:gosec // G401: the legacy format under test
	h.Write(data)
	h.Write(be32([]byte{0x00}, created))
	digest := h.Sum(nil)
	r, s, err := dsa.Sign(rand.Reader, k.dsa, digest)
	if err != nil {
		t.Fatal(err)
	}
	body := be32([]byte{3, 5, 0x00}, created)
	body = append(append(body, k.keyID()...), 17, 2, digest[0], digest[1])
	return Armor("PGP SIGNATURE", oldPacket(2, append(body, mpis(r, s)...)))
}

// Packet is a new-format packet with a one-, two- or five-octet length.
func Packet(tag byte, body []byte) []byte {
	out := []byte{0xC0 | tag}
	switch n := len(body); {
	case n < 192:
		out = append(out, byte(n))
	case n < 8384:
		n -= 192
		out = be16(out, n+192<<8)
	default:
		out = be32(append(out, 255), uint32(n)) //nolint:gosec // G115: test packets are small
	}
	return append(out, body...)
}

// oldPacket is an old-format packet with a one-octet length (as Dell's v3 signature).
func oldPacket(tag byte, body []byte) []byte {
	return append([]byte{0x80 | tag<<2, byte(len(body) & 0xFF)}, body...)
}

// Armor wraps raw packets in ASCII armor with a CRC-24 checksum.
func Armor(kind string, raw []byte) []byte {
	var b strings.Builder
	b.WriteString("-----BEGIN " + kind + "-----\nVersion: catalogtest\n\n")
	enc := base64.StdEncoding.EncodeToString(raw)
	for len(enc) > 64 {
		b.WriteString(enc[:64] + "\n")
		enc = enc[64:]
	}
	b.WriteString(enc + "\n")
	c := crc24(raw)
	b.WriteString("=" + base64.StdEncoding.EncodeToString(be32(nil, c)[1:]) + "\n")
	b.WriteString("-----END " + kind + "-----\n")
	return []byte(b.String())
}

// ArmorPackets wraps raw signature packets in signature armor (for malformed cases).
func ArmorPackets(t testing.TB, raw []byte) []byte {
	t.Helper()
	return Armor("PGP SIGNATURE", raw)
}

// Dearmor returns the packets inside an armored block (the test helper's own armor).
func Dearmor(t testing.TB, armored []byte) []byte {
	t.Helper()
	var b64 strings.Builder
	in := false
	for _, l := range strings.Split(string(armored), "\n") {
		switch {
		case strings.HasPrefix(l, "-----BEGIN"):
			in = true
		case strings.HasPrefix(l, "-----END"):
			in = false
		case in && l != "" && !strings.Contains(l, ":") && !strings.HasPrefix(l, "="):
			b64.WriteString(l)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func crc24(b []byte) uint32 {
	c := uint32(0xB704CE)
	for _, x := range b {
		c ^= uint32(x) << 16
		for range 8 {
			c <<= 1
			if c&0x1000000 != 0 {
				c ^= 0x1864CFB
			}
		}
	}
	return c & 0xFFFFFF
}

// be16 and be32 append big-endian integers (n is a packet length: at most 0xFFFF here).
func be16(b []byte, n int) []byte { return binary.BigEndian.AppendUint16(b, uint16(n&0xFFFF)) }

func be32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }

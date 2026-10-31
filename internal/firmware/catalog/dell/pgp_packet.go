package dell

import (
	"crypto"
	"crypto/dsa" //nolint:staticcheck // SA1019: Dell signs its catalog with DSA; verification only
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // G505: the v4 key fingerprint is defined as SHA-1 (RFC 4880 §12.2)
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// Packet tags and algorithm IDs (RFC 4880 §4.3, §9).
const (
	tagSignature = 2
	tagPublicKey = 6

	algoRSA         = 1
	algoRSASignOnly = 3
	algoDSA         = 17

	sigTypeBinary = 0x00
	maxPacketLen  = 64 << 10
)

var errPacket = errors.New("malformed OpenPGP packet")

type packet struct {
	tag  byte
	body []byte
}

// packets splits b into packets. Partial and indeterminate lengths are refused: neither
// occurs in keys or detached signatures.
func packets(b []byte) ([]packet, error) {
	var out []packet
	for len(b) > 0 {
		p, rest, err := nextPacket(b)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
		b = rest
	}
	return out, nil
}

func nextPacket(b []byte) (packet, []byte, error) {
	if len(b) < 2 || b[0]&0x80 == 0 {
		return packet{}, nil, errPacket
	}
	var tag byte
	var n, hdr int
	if b[0]&0x40 != 0 { // new format
		tag = b[0] & 0x3F
		switch l := int(b[1]); {
		case l < 192:
			n, hdr = l, 2
		case l < 224 && len(b) >= 3:
			n, hdr = (l-192)<<8+int(b[2])+192, 3
		case l == 255 && len(b) >= 6:
			n, hdr = int(binary.BigEndian.Uint32(b[2:6])), 6
		default:
			return packet{}, nil, errPacket // partial body length
		}
	} else { // old format
		tag = (b[0] >> 2) & 0x0F
		switch b[0] & 3 {
		case 0:
			n, hdr = int(b[1]), 2
		case 1:
			if len(b) < 3 {
				return packet{}, nil, errPacket
			}
			n, hdr = int(binary.BigEndian.Uint16(b[1:3])), 3
		case 2:
			if len(b) < 5 {
				return packet{}, nil, errPacket
			}
			n, hdr = int(binary.BigEndian.Uint32(b[1:5])), 5
		default:
			return packet{}, nil, errPacket // indeterminate length
		}
	}
	if n < 0 || n > maxPacketLen || hdr+n > len(b) {
		return packet{}, nil, errPacket
	}
	return packet{tag: tag, body: b[hdr : hdr+n]}, b[hdr+n:], nil
}

// mpi reads a multiprecision integer (RFC 4880 §3.2).
func mpi(b []byte) (*big.Int, []byte, error) {
	if len(b) < 2 {
		return nil, nil, errPacket
	}
	n := (int(binary.BigEndian.Uint16(b)) + 7) / 8
	if len(b) < 2+n || n == 0 {
		return nil, nil, errPacket
	}
	return new(big.Int).SetBytes(b[2 : 2+n]), b[2+n:], nil
}

// pubKey is a v4 primary public key.
type pubKey struct {
	fingerprint string // 40 upper-case hex digits
	keyID       uint64
	algo        byte
	rsa         *rsa.PublicKey
	dsa         *dsa.PublicKey
}

// parsePublicKey reads a v4 public key packet body (RSA or DSA).
func parsePublicKey(body []byte) (pubKey, error) {
	if len(body) < 6 || body[0] != 4 {
		return pubKey{}, fmt.Errorf("%w: only v4 public keys are supported", errPacket)
	}
	k := pubKey{algo: body[5]}
	rest := body[6:]
	var err error
	switch k.algo {
	case algoRSA, algoRSASignOnly:
		var n, e *big.Int
		if n, rest, err = mpi(rest); err == nil {
			e, _, err = mpi(rest)
		}
		if err != nil || e.BitLen() > 32 || e.Int64() < 3 || e.Bit(0) == 0 || n.BitLen() < 2048 || n.BitLen() > 16384 {
			return pubKey{}, fmt.Errorf("%w: RSA key (2048-16384 bits, odd exponent ≥ 3)", errPacket)
		}
		k.rsa = &rsa.PublicKey{N: n, E: int(e.Int64())}
	case algoDSA:
		var p, q, g, y *big.Int
		for _, dst := range []**big.Int{&p, &q, &g, &y} {
			if *dst, rest, err = mpi(rest); err != nil {
				return pubKey{}, err
			}
		}
		k.dsa = &dsa.PublicKey{Parameters: dsa.Parameters{P: p, Q: q, G: g}, Y: y}
		if !saneDSA(k.dsa) {
			return pubKey{}, fmt.Errorf("%w: DSA parameters out of range", errPacket)
		}
	default:
		return pubKey{}, fmt.Errorf("%w: unsupported key algorithm %d", errPacket, k.algo)
	}
	h := sha1.New()                                                                //nolint:gosec // G401: the v4 fingerprint is SHA-1 by definition
	h.Write(binary.BigEndian.AppendUint16([]byte{0x99}, uint16(len(body)&0xFFFF))) // body ≤ maxPacketLen < 64 KiB
	h.Write(body)
	fp := h.Sum(nil)
	k.fingerprint = fmt.Sprintf("%X", fp)
	k.keyID = binary.BigEndian.Uint64(fp[12:20])
	return k, nil
}

// signature is a parsed v3 or v4 signature packet.
type signature struct {
	version  byte
	sigType  byte
	algo     byte
	hash     crypto.Hash
	issuer   uint64
	issuerFP string // hashed issuer fingerprint (v4), "" when absent
	expires  uint32 // hashed signature expiration, seconds after created (0: none)
	created  uint32
	hashTag  [2]byte
	trailer  []byte // what is hashed after the data
	r, s     *big.Int
	rsaValue []byte
}

func hashOf(id byte) (crypto.Hash, bool) {
	switch id {
	case 2:
		return crypto.SHA1, true
	case 8:
		return crypto.SHA256, true
	case 9:
		return crypto.SHA384, true
	case 10:
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

func parseSignature(body []byte) (signature, error) {
	if len(body) < 1 {
		return signature{}, errPacket
	}
	var sig signature
	var rest []byte
	var err error
	switch body[0] {
	case 3:
		sig, rest, err = parseV3(body)
	case 4:
		sig, rest, err = parseV4(body)
	default:
		return signature{}, fmt.Errorf("%w: signature version %d", errPacket, body[0])
	}
	if err != nil {
		return signature{}, err
	}
	switch sig.algo {
	case algoRSA, algoRSASignOnly:
		if len(rest) < 2 {
			return signature{}, errPacket
		}
		n := (int(binary.BigEndian.Uint16(rest)) + 7) / 8
		if len(rest) != 2+n {
			return signature{}, errPacket
		}
		sig.rsaValue = rest[2:]
	case algoDSA:
		if sig.r, rest, err = mpi(rest); err == nil {
			sig.s, rest, err = mpi(rest)
		}
		if err != nil || len(rest) != 0 {
			return signature{}, errPacket
		}
	default:
		return signature{}, fmt.Errorf("%w: unsupported signature algorithm %d", errPacket, sig.algo)
	}
	return sig, nil
}

// parseV3: version, 5 (hashed length), type, time(4), issuer(8), algo, hash, tag(2).
func parseV3(b []byte) (signature, []byte, error) {
	if len(b) < 19 || b[1] != 5 {
		return signature{}, nil, errPacket
	}
	h, ok := hashOf(b[16])
	if !ok {
		return signature{}, nil, fmt.Errorf("%w: unsupported hash", errPacket)
	}
	sig := signature{version: 3, sigType: b[2], algo: b[15], hash: h, issuer: binary.BigEndian.Uint64(b[7:15]),
		created: binary.BigEndian.Uint32(b[3:7]), hashTag: [2]byte{b[17], b[18]}, trailer: append([]byte(nil), b[2:7]...)}
	return sig, b[19:], nil
}

// parseV4: version, type, algo, hash, hashed subpackets, unhashed subpackets, tag(2).
func parseV4(b []byte) (signature, []byte, error) {
	if len(b) < 6 {
		return signature{}, nil, errPacket
	}
	h, ok := hashOf(b[3])
	if !ok {
		return signature{}, nil, fmt.Errorf("%w: unsupported hash", errPacket)
	}
	sig := signature{version: 4, sigType: b[1], algo: b[2], hash: h}
	hl := int(binary.BigEndian.Uint16(b[4:6]))
	if len(b) < 6+hl+2 {
		return signature{}, nil, errPacket
	}
	hashed := b[6 : 6+hl]
	ul := int(binary.BigEndian.Uint16(b[6+hl : 8+hl]))
	if len(b) < 8+hl+ul+2 {
		return signature{}, nil, errPacket
	}
	unhashed := b[8+hl : 8+hl+ul]
	if err := sig.subpackets(hashed, true); err != nil {
		return signature{}, nil, err
	}
	if err := sig.subpackets(unhashed, false); err != nil {
		return signature{}, nil, err
	}
	sig.hashTag = [2]byte{b[8+hl+ul], b[9+hl+ul]}
	// Trailer: the hashed part of the packet, then 0x04 0xFF and its length (§5.2.4).
	n := 6 + hl
	sig.trailer = binary.BigEndian.AppendUint32(append(append([]byte(nil), b[:n]...), 0x04, 0xFF), uint32(n)) //nolint:gosec // G115: n ≤ 65541
	return sig, b[10+hl+ul:], nil
}

// subpackets reads the creation time (2), expiration (3), issuer (16) and issuer
// fingerprint (33). Hashed (authenticated) data wins: an unhashed issuer is used only
// when the hashed area names none, and a hashed key ID and fingerprint must agree. An
// unknown critical subpacket in the hashed area fails the signature (§5.2.3.1).
func (sig *signature) subpackets(b []byte, hashed bool) error {
	unhashedIssuer := uint64(0)
	for len(b) > 0 {
		var n, hdr int
		switch l := int(b[0]); {
		case l < 192:
			n, hdr = l, 1
		case l < 255 && len(b) >= 2:
			n, hdr = (l-192)<<8+int(b[1])+192, 2
		case l == 255 && len(b) >= 5:
			n, hdr = int(binary.BigEndian.Uint32(b[1:5])), 5
		default:
			return errPacket
		}
		if n < 1 || hdr+n > len(b) {
			return errPacket
		}
		id, err := sig.subpacket(b[hdr]&0x7F, b[hdr]&0x80 != 0, b[hdr+1:hdr+n], hashed)
		if err != nil {
			return err
		}
		if id != 0 && !hashed {
			unhashedIssuer = id
		}
		b = b[hdr+n:]
	}
	if !hashed && sig.issuer == 0 {
		sig.issuer = unhashedIssuer
	}
	return nil
}

// subpacket applies one subpacket and returns the issuer key ID it names (0: none).
func (sig *signature) subpacket(typ byte, critical bool, data []byte, hashed bool) (uint64, error) {
	var id uint64
	switch {
	case typ == 16 && len(data) == 8:
		id = binary.BigEndian.Uint64(data)
	case typ == 33 && len(data) == 21 && data[0] == 4:
		id = binary.BigEndian.Uint64(data[13:21])
		if hashed {
			sig.issuerFP = fmt.Sprintf("%X", data[1:21])
		}
	case typ == 2 && len(data) == 4 && hashed:
		sig.created = binary.BigEndian.Uint32(data)
	case typ == 3 && len(data) == 4 && hashed:
		sig.expires = binary.BigEndian.Uint32(data)
	case (typ == 2 || typ == 3) && hashed:
		return 0, fmt.Errorf("%w: malformed time subpacket", errPacket)
	case typ == 2 || typ == 3 || typ == 16 || typ == 33:
	case hashed && critical:
		return 0, fmt.Errorf("%w: unknown critical subpacket %d", errPacket, typ)
	}
	if id != 0 && hashed {
		if sig.issuer != 0 && sig.issuer != id {
			return 0, fmt.Errorf("%w: the hashed issuer subpackets disagree", errPacket)
		}
		sig.issuer = id
	}
	return id, nil
}

// verify checks sig over the data digest state h (data already written) with key k.
func (sig signature) verify(k pubKey, digest []byte) bool {
	if digest[0] != sig.hashTag[0] || digest[1] != sig.hashTag[1] {
		return false
	}
	if sig.issuerFP != "" && sig.issuerFP != k.fingerprint {
		return false
	}
	switch {
	case k.rsa != nil && (sig.algo == algoRSA || sig.algo == algoRSASignOnly):
		// An MPI drops leading zero bytes; PKCS#1 wants the value at the modulus size.
		size := k.rsa.Size()
		if len(sig.rsaValue) > size {
			return false
		}
		v := make([]byte, size)
		copy(v[size-len(sig.rsaValue):], sig.rsaValue)
		return rsa.VerifyPKCS1v15(k.rsa, sig.hash, digest, v) == nil
	case k.dsa != nil && sig.algo == algoDSA:
		d := digest
		if q := (k.dsa.Q.BitLen() + 7) / 8; len(d) > q { // FIPS 186-3 §4.6
			d = d[:q]
		}
		return dsa.Verify(k.dsa, d, sig.r, sig.s)
	default:
		return false
	}
}

// saneDSA checks DSA domain parameters (FIPS 186: P 1024-3072 bits, Q 160/224/256 bits
// dividing P-1, both prime, G of order Q, 1 < Y < P), so a crafted key cannot make
// forgery trivial.
func saneDSA(k *dsa.PublicKey) bool {
	p, q, g, y := k.P, k.Q, k.G, k.Y
	one := big.NewInt(1)
	pm1 := new(big.Int).Sub(p, one)
	switch {
	case p.BitLen() < 1024 || p.BitLen() > 3072:
		return false
	case q.BitLen() != 160 && q.BitLen() != 224 && q.BitLen() != 256:
		return false
	case new(big.Int).Mod(pm1, q).Sign() != 0:
		return false
	case g.Cmp(one) <= 0 || g.Cmp(p) >= 0 || y.Cmp(one) <= 0 || y.Cmp(p) >= 0:
		return false
	case new(big.Int).Exp(g, q, p).Cmp(one) != 0:
		return false
	}
	return q.ProbablyPrime(20) && p.ProbablyPrime(20)
}

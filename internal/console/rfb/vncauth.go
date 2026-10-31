package rfb

import (
	"crypto/des" //nolint:gosec // G502: RFB VNC authentication (RFC 6143 §7.2.2) is defined over DES; see doc.go
	"math/bits"
)

// VNCAuthKeyLen is how many password bytes VNC authentication uses. Longer passwords
// are silently truncated by the protocol; iDRAC also uses only the first 8.
const VNCAuthKeyLen = 8

// VNCAuthResponse encrypts the server's 16-byte challenge with DES (ECB, two blocks)
// keyed by the first 8 password bytes, zero padded, with every key byte bit-reversed
// (RFC 6143 §7.2.2 errata; the historic VNC convention).
//
// This is weak by design of the protocol: a passive observer of challenge and
// response can brute-force the 56-bit key offline. The relay therefore prefers a TLS
// wrapped VNC port (docs/security.md, "VNC DES weakness").
func VNCAuthResponse(challenge [16]byte, password []byte) [16]byte {
	var key [VNCAuthKeyLen]byte
	copy(key[:], password)
	for i := range key {
		key[i] = bits.Reverse8(key[i])
	}
	block, err := des.NewCipher(key[:]) //nolint:gosec // G401/G405: protocol-mandated DES, see above
	if err != nil {
		panic(err) // unreachable: the key is always 8 bytes
	}
	var out [16]byte
	block.Encrypt(out[:8], challenge[:8])
	block.Encrypt(out[8:], challenge[8:])
	clear(key[:])
	return out
}

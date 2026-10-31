// Package tlspin is the one implementation of "trust exactly this public key" TLS: the
// SHA-256 of a certificate's SubjectPublicKeyInfo (SPKI) replaces chain verification
// (it is never simply skipped). VerifyConnection runs on every full and resumed
// handshake, compares in constant time and fails closed: no certificate, a malformed
// pin or no match refuses the connection with the caller's mismatch error.
//
// Two modes: Leaf (the BMC drivers: self-signed BMC certificates) and AnyInChain (the
// GELF shipper, tech_doc §34): the leaf or an issuing CA the leaf verifiably chains to,
// so pinning the CA lets a log server rotate its leaf without a new pin.
package tlspin

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
)

// Mode says which presented certificates may carry the pinned key.
type Mode int

// Modes.
const (
	// Leaf: only the server's own (first) certificate.
	Leaf Mode = iota
	// AnyInChain: the leaf, or a CA certificate the server sends that the leaf chains to
	// (signature and validity checked).
	AnyInChain
)

// ErrExpired wraps the mismatch error when an issuer pin failed only because the leaf
// (or the CA) is outside its validity period: the log server needs a renewed
// certificate, nothing suggests an impostor.
var ErrExpired = errors.New("tlspin: certificate expired or not yet valid")

// errNoMatch is returned when a caller passes no mismatch error (still fails closed).
var errNoMatch = errors.New("tlspin: certificate does not match the pin")

// maxChain bounds how many presented certificates are hashed.
const maxChain = 8

// Hex is the hex SHA-256 of c's SubjectPublicKeyInfo: the value config files store.
func Hex(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// ParseHex decodes a pin: exactly 64 lower-case hex digits.
func ParseHex(s string) ([]byte, error) {
	if len(s) != 2*sha256.Size {
		return nil, fmt.Errorf("tlspin: a pin is %d hex digits", 2*sha256.Size)
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return nil, errors.New("tlspin: a pin is lower-case hex")
		}
	}
	return hex.DecodeString(s)
}

// Config returns a fresh client config (TLS 1.2 minimum) that accepts a handshake only
// when the pinned SPKI is presented, per mode. pin is copied. mismatch is the error a
// refused handshake returns (wrapped when no certificate was sent). With AnyInChain and
// no name an issuer match is refused: use IssuerConfig.
func Config(pin []byte, mode Mode, mismatch error) *tls.Config {
	return config(pin, mode, "", mismatch)
}

// IssuerConfig is the AnyInChain config: the leaf, or an issuing CA when the leaf chains
// to it AND is valid for name (a DNS name or an IP literal: the log server's server name
// or host). Without the name check, an issuer pin on a CA that also signs other
// certificates (a public CA in particular) would accept any certificate it ever issued.
func IssuerConfig(pin []byte, name string, mismatch error) *tls.Config {
	return config(pin, AnyInChain, name, mismatch)
}

func config(pin []byte, mode Mode, name string, mismatch error) *tls.Config {
	want := append([]byte(nil), pin...)
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // replaced by the SPKI pin check in VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			return Verify(cs, want, mode, name, mismatch)
		},
	}
}

// Verify applies the pin to a handshake's presented certificates. A leaf pin matches the
// server's own certificate, whose key the handshake has proven. An issuer pin
// (AnyInChain) matches a later certificate C only when the leaf chains to C: signature
// and validity are verified with C as the only root (no system roots), because a CA
// certificate is public and an impostor could simply send it along, and the leaf must be
// valid for name (an empty name refuses every issuer match).
func Verify(cs tls.ConnectionState, pin []byte, mode Mode, name string, mismatch error) error {
	if mismatch == nil {
		mismatch = errNoMatch
	}
	peers := cs.PeerCertificates
	if len(peers) == 0 {
		return fmt.Errorf("%w: no peer certificate", mismatch)
	}
	if matches(peers[0], pin) {
		return nil
	}
	if mode != AnyInChain || name == "" || peers[0].VerifyHostname(name) != nil {
		return mismatch
	}
	peers = peers[:min(len(peers), maxChain)]
	expired := false
	for i := 1; i < len(peers); i++ {
		if !matches(peers[i], pin) {
			continue
		}
		err := chainError(peers[0], peers[1:i], peers[i])
		if err == nil {
			return nil
		}
		var ci x509.CertificateInvalidError
		expired = expired || (errors.As(err, &ci) && ci.Reason == x509.Expired)
	}
	if expired {
		// The right CA, the right name, only outside its validity: not an impostor.
		return fmt.Errorf("%w: %w", ErrExpired, mismatch)
	}
	return mismatch
}

func matches(c *x509.Certificate, pin []byte) bool {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return subtle.ConstantTimeCompare(sum[:], pin) == 1 // false for a short or nil pin
}

// ChainsTo reports whether leaf verifies up to root through the given intermediates
// (signature and validity; no host name, no system roots).
func ChainsTo(leaf *x509.Certificate, intermediates []*x509.Certificate, root *x509.Certificate) bool {
	return chainError(leaf, intermediates, root) == nil
}

func chainError(leaf *x509.Certificate, intermediates []*x509.Certificate, root *x509.Certificate) error {
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, c := range intermediates {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err
}

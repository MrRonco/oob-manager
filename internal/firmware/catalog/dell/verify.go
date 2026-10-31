package dell

import (
	"bytes"
	"crypto"
	_ "crypto/sha256" // registers SHA-256 for crypto.Hash.New
	_ "crypto/sha512" // registers SHA-384 and SHA-512
	_ "embed"
	"errors"
	"fmt"
	"io"
	"time"

	"oob-manager/internal/firmware/catalog"
)

// DellFingerprint is the fingerprint of the key Dell signs its catalog with ("Dell, Inc.
// (Product Group)", DSA-1024, created 2001-04-16). The armored key is embedded from
// https://linux.dell.com/files/pgp_pubkeys/0xca77951d23b66a9d.asc (also on the public
// keyservers).
const DellFingerprint = "4172E2CE955A1776A5E61BB7CA77951D23B66A9D"

// MaxSignatureBytes caps the armored detached signature (Dell's is 194 bytes).
const MaxSignatureBytes = 4 << 10

// maxKeysBytes and maxKeys cap an armored key file (each DSA key costs a primality test).
const (
	maxKeysBytes = 1 << 20
	maxKeys      = 32
)

//go:embed dell-ca77951d.asc
var dellKey []byte

// Keys are the trusted signing keys: Dell's embedded key (legacy: SHA-1 accepted) and
// the primary keys of firmware.catalog.extra_keys_file (SHA-2 only). Only primary keys
// sign: subkeys are ignored.
type Keys struct {
	byID   map[uint64]pubKey
	legacy map[uint64]bool
	order  []string // fingerprints, in load order
}

// LoadKeys returns Dell's key plus the armored keys in extra (nil: none). The embedded
// key must have DellFingerprint.
func LoadKeys(extra []byte) (Keys, error) {
	k := Keys{byID: map[uint64]pubKey{}, legacy: map[uint64]bool{}}
	dell, err := primaryKeys(dellKey)
	if err != nil || len(dell) != 1 || dell[0].fingerprint != DellFingerprint {
		return Keys{}, errors.New("dell: the embedded signing key is not the pinned Dell key")
	}
	if err := k.add(dell[0], true); err != nil {
		return Keys{}, err
	}
	if len(bytes.TrimSpace(extra)) > 0 {
		more, err := primaryKeys(extra)
		if err != nil {
			return Keys{}, fmt.Errorf("dell: extra trusted keys: %w", err)
		}
		for _, p := range more {
			if err := k.add(p, false); err != nil {
				return Keys{}, fmt.Errorf("dell: extra trusted keys: %w", err)
			}
		}
	}
	return k, nil
}

// primaryKeys reads every v4 primary public key (RSA or DSA) of the armored blocks.
func primaryKeys(data []byte) ([]pubKey, error) {
	if len(data) > maxKeysBytes {
		return nil, errors.New("key file too large")
	}
	blocks, err := dearmor(data, armorPublicKey)
	if err != nil {
		return nil, err
	}
	var out []pubKey
	for _, b := range blocks {
		ps, err := packets(b)
		if err != nil {
			return nil, err
		}
		for _, p := range ps {
			if p.tag != tagPublicKey {
				continue
			}
			if len(out) == maxKeys {
				return nil, fmt.Errorf("more than %d keys in the file", maxKeys)
			}
			k, err := parsePublicKey(p.body)
			if err != nil {
				return nil, err
			}
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no public key in the file")
	}
	return out, nil
}

// add trusts p; a key ID shared by a different key is refused (a 64-bit collision would
// otherwise hide one of them).
func (k *Keys) add(p pubKey, legacy bool) error {
	if prev, dup := k.byID[p.keyID]; dup {
		if prev.fingerprint == p.fingerprint {
			return nil
		}
		return fmt.Errorf("two trusted keys share the key ID %016X", p.keyID)
	}
	k.byID[p.keyID], k.legacy[p.keyID] = p, legacy
	k.order = append(k.order, p.fingerprint)
	return nil
}

// Fingerprints lists the trusted keys' fingerprints (for the settings page).
func (k Keys) Fingerprints() []string { return append([]string(nil), k.order...) }

// Verify checks sig, an armored detached signature over artifact (now: the clock for a
// hashed signature expiration). The armor is at most
// MaxSignatureBytes and holds exactly one v3 or v4 signature packet over binary data; its
// issuer must be a trusted key (else ErrUntrustedKey, naming the key ID so an admin can
// check it); the hash is SHA-2, or SHA-1 from a legacy key. Any failure is ErrSignature.
func (k Keys) Verify(artifact io.Reader, sig []byte) (catalog.Signer, error) {
	return k.verifyAt(artifact, sig, time.Now())
}

func (k Keys) verifyAt(artifact io.Reader, sig []byte, now time.Time) (catalog.Signer, error) {
	if len(sig) > MaxSignatureBytes {
		return catalog.Signer{}, fmt.Errorf("%w: the signature file is larger than %d bytes", catalog.ErrSignature, MaxSignatureBytes)
	}
	s, err := oneSignature(sig)
	if err != nil {
		return catalog.Signer{}, err
	}
	key, trusted := k.byID[s.issuer]
	if !trusted {
		return catalog.Signer{}, fmt.Errorf("%w: key ID %016X", catalog.ErrUntrustedKey, s.issuer)
	}
	legacy := k.legacy[s.issuer]
	if !hashAllowed(s.hash, legacy) {
		return catalog.Signer{}, fmt.Errorf("%w: hash algorithm not accepted for this key", catalog.ErrSignature)
	}
	if s.expires != 0 && now.Unix() > int64(s.created)+int64(s.expires) {
		return catalog.Signer{}, fmt.Errorf("%w: the signature has expired", catalog.ErrSignature)
	}
	h := s.hash.New()
	if _, err := io.Copy(h, artifact); err != nil {
		return catalog.Signer{}, fmt.Errorf("dell: reading the catalog: %w", err)
	}
	h.Write(s.trailer)
	if !s.verify(key, h.Sum(nil)) {
		return catalog.Signer{}, fmt.Errorf("%w: the signature does not match", catalog.ErrSignature)
	}
	return catalog.Signer{Fingerprint: key.fingerprint, KeyID: fmt.Sprintf("%016X", s.issuer), Legacy: legacy}, nil
}

func oneSignature(armored []byte) (signature, error) {
	blocks, err := dearmor(armored, armorSignature)
	if err != nil || len(blocks) != 1 {
		return signature{}, fmt.Errorf("%w: not one armored PGP signature", catalog.ErrSignature)
	}
	ps, err := packets(blocks[0])
	if err != nil || len(ps) != 1 || ps[0].tag != tagSignature {
		return signature{}, fmt.Errorf("%w: not exactly one signature packet", catalog.ErrSignature)
	}
	s, err := parseSignature(ps[0].body)
	if err != nil {
		return signature{}, fmt.Errorf("%w: %v", catalog.ErrSignature, err)
	}
	if s.sigType != sigTypeBinary {
		return signature{}, fmt.Errorf("%w: not a signature over binary data", catalog.ErrSignature)
	}
	if s.issuer == 0 {
		return signature{}, fmt.Errorf("%w: the signature names no issuer", catalog.ErrSignature)
	}
	return s, nil
}

func hashAllowed(h crypto.Hash, legacy bool) bool {
	switch h {
	case crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return true
	case crypto.SHA1:
		return legacy
	default:
		return false
	}
}

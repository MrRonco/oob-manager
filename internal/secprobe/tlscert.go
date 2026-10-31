package secprobe

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/textclean"
)

// maxCertText caps certificate name fields (they come from the peer).
const maxCertText = 200

// certFacts describes a leaf certificate for the checks.
func certFacts(c *x509.Certificate) bmc.CertFacts {
	sum := sha256.Sum256(c.Raw)
	f := bmc.CertFacts{
		SHA256:         hex.EncodeToString(sum[:]),
		Subject:        textclean.Clean(c.Subject.String(), maxCertText),
		Issuer:         textclean.Clean(c.Issuer.String(), maxCertText),
		SubjectOrg:     textclean.Clean(strings.Join(c.Subject.Organization, ", "), maxCertText),
		SubjectOrgUnit: textclean.Clean(strings.Join(c.Subject.OrganizationalUnit, ", "), maxCertText),
		SubjectCN:      textclean.Clean(c.Subject.CommonName, maxCertText),
		NotBefore:      c.NotBefore.UTC(),
		NotAfter:       c.NotAfter.UTC(),
		SelfSigned:     selfSigned(c),
		Signature:      c.SignatureAlgorithm.String(),
	}
	f.KeyType, f.KeyBits = keyOf(c)
	return f
}

// selfSigned: the issuer is the subject and the certificate's own key verifies its
// signature. Go refuses to verify SHA-1 and MD5 signatures at all; with a matching name
// such a certificate still counts as self-signed (its signature algorithm is a finding
// of its own).
func selfSigned(c *x509.Certificate) bool {
	if !bytes.Equal(c.RawIssuer, c.RawSubject) {
		return false
	}
	err := c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
	var weak x509.InsecureAlgorithmError
	return err == nil || errors.As(err, &weak)
}

func keyOf(c *x509.Certificate) (string, int) {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return "unknown", 0
	}
}

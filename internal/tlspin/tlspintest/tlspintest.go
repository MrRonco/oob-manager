// Package tlspintest generates throwaway certificates for tests of pinned TLS: a
// self-signed leaf, or a leaf issued by a test CA (served with its chain). Keys are
// ECDSA P-256 generated per call; nothing is ever written to disk.
package tlspintest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"time"
)

// TB is the subset of testing.TB the helpers need.
type TB interface {
	Helper()
	Fatal(args ...any)
}

// Cert is one generated certificate with its key.
type Cert struct {
	X509 *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// SPKI is the hex SHA-256 of the certificate's SubjectPublicKeyInfo (the pin).
func (c Cert) SPKI() string {
	sum := sha256.Sum256(c.X509.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// Pair is what a TLS server presents: a leaf and, for an issued leaf, its CA.
type Pair struct {
	Leaf Cert
	CA   *Cert // nil for a self-signed leaf
}

// TLS is the tls.Certificate to serve: the leaf, followed by the CA when there is one.
func (p Pair) TLS() tls.Certificate {
	chain := [][]byte{p.Leaf.X509.Raw}
	if p.CA != nil {
		chain = append(chain, p.CA.X509.Raw)
	}
	return tls.Certificate{Certificate: chain, PrivateKey: p.Leaf.Key, Leaf: p.Leaf.X509}
}

// SPKIs are the pins of the leaf, then of the CA when there is one.
func (p Pair) SPKIs() []string {
	out := []string{p.Leaf.SPKI()}
	if p.CA != nil {
		out = append(out, p.CA.SPKI())
	}
	return out
}

// LeafOnly is p served without its chain (a server that sends only the leaf).
func (p Pair) LeafOnly() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{p.Leaf.X509.Raw}, PrivateKey: p.Leaf.Key, Leaf: p.Leaf.X509}
}

// SelfSigned returns a self-signed leaf for 127.0.0.1 and "gelf.example.test".
func SelfSigned(t TB) Pair {
	t.Helper()
	key := newKey(t)
	tmpl := leafTemplate("gelf.example.test")
	return Pair{Leaf: Cert{X509: create(t, tmpl, tmpl, &key.PublicKey, key), Key: key}}
}

// Issued returns a leaf issued by a fresh test CA for 127.0.0.1 and "gelf.example.test".
func Issued(t TB) Pair {
	t.Helper()
	return IssuedFor(t, "gelf.example.test", "127.0.0.1")
}

// IssuedFor returns a leaf issued by a fresh test CA for the given names (DNS names or
// IP literals; the first is also the common name).
func IssuedFor(t TB, names ...string) Pair {
	t.Helper()
	return issued(t, false, names)
}

// IssuedExpired is Issued with a leaf that expired a day ago (the CA is still valid).
func IssuedExpired(t TB) Pair {
	t.Helper()
	return issued(t, true, []string{"gelf.example.test", "127.0.0.1"})
}

func issued(t TB, expired bool, names []string) Pair {
	t.Helper()
	caKey := newKey(t)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test log CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	ca := Cert{X509: create(t, caTmpl, caTmpl, &caKey.PublicKey, caKey), Key: caKey}
	key := newKey(t)
	tmpl := leafFor(names)
	if expired {
		tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
	}
	leaf := Cert{X509: create(t, tmpl, ca.X509, &key.PublicKey, caKey), Key: key}
	return Pair{Leaf: leaf, CA: &ca}
}

// leafFor is a leaf template for names: IP literals become IP SANs, the rest DNS names.
func leafFor(names []string) *x509.Certificate {
	tmpl := leafTemplate(names[0])
	tmpl.DNSNames, tmpl.IPAddresses = nil, nil
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	return tmpl
}

func leafTemplate(name string) *x509.Certificate {
	return &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{name}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
}

func newKey(t TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func create(t TB, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

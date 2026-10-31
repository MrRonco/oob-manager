package rfbtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

// serverTLS is the listener's TLS config. rsaKexOnly emulates an iDRAC8 2.8x VNC port:
// TLS 1.2 only, an RSA certificate and nothing but RSA key-exchange suites.
func serverTLS(cert tls.Certificate, rsaKexOnly bool) *tls.Config {
	c := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if rsaKexOnly {
		c.MaxVersion = tls.VersionTLS12
		c.CipherSuites = []uint16{ //nolint:gosec // G402: deliberately emulates an old BMC
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		}
	}
	return c
}

// selfSigned makes a throwaway certificate: ECDSA P-256, or RSA-2048 when rsaKey is set
// (RSA key exchange needs an RSA certificate).
func selfSigned(rsaKey bool) (tls.Certificate, error) {
	key, pub, usage, err := newKey(rsaKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake-bmc-vnc"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: usage,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func newKey(rsaKey bool) (crypto.Signer, crypto.PublicKey, x509.KeyUsage, error) {
	if rsaKey {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, 0, err
		}
		return k, &k.PublicKey, x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, 0, err
	}
	return k, &k.PublicKey, x509.KeyUsageDigitalSignature, nil
}

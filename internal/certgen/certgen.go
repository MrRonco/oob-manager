// Package certgen creates the self-signed ECDSA P-256 certificate the UI listener can
// use until it is replaced with a certificate from your own CA (deploy/README.md).
package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// Limits. 825 days is the longest validity Apple platforms accept for a TLS server
// certificate; anything longer is rejected by Safari even when trusted.
const (
	MaxValidity = 825 * 24 * time.Hour
	MaxHosts    = 32
	minValidity = 24 * time.Hour
	clockSkew   = 5 * time.Minute
)

// Request describes the certificate. Hosts are IP addresses or DNS names; the first one
// is also the subject common name. A zero Validity means MaxValidity; a zero Now means
// time.Now.
type Request struct {
	Hosts    []string
	Validity time.Duration
	Now      time.Time
}

// Pair is a PEM certificate and its PKCS#8 PEM private key. KeyPEM is a secret.
type Pair struct {
	CertPEM []byte
	KeyPEM  []byte
	SHA256  string // hex SHA-256 of the DER certificate, for comparing with a browser
}

// Generate creates a self-signed server certificate for r.
func Generate(r Request) (Pair, error) {
	ips, dns, err := splitHosts(r.Hosts)
	if err != nil {
		return Pair{}, err
	}
	validity, err := validityOf(r.Validity)
	if err != nil {
		return Pair{}, err
	}
	now := r.Now
	if now.IsZero() {
		now = time.Now()
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Pair{}, fmt.Errorf("certgen: key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return Pair{}, fmt.Errorf("certgen: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: r.Hosts[0], Organization: []string{"oob-manager"}},
		NotBefore: now.Add(-clockSkew), NotAfter: now.Add(validity),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IPAddresses: ips, DNSNames: dns,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return Pair{}, fmt.Errorf("certgen: certificate: %w", err)
	}
	return encode(der, key)
}

func encode(der []byte, key *ecdsa.PrivateKey) (Pair, error) {
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Pair{}, fmt.Errorf("certgen: key encoding: %w", err)
	}
	sum := sha256.Sum256(der)
	return Pair{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}),
		SHA256:  hex.EncodeToString(sum[:]),
	}, nil
}

func validityOf(v time.Duration) (time.Duration, error) {
	switch {
	case v == 0:
		return MaxValidity, nil
	case v < minValidity || v > MaxValidity:
		return 0, fmt.Errorf("certgen: validity must be between 1 day and %d days", int(MaxValidity.Hours()/24))
	default:
		return v, nil
	}
}

// splitHosts sorts hosts into IP and DNS SANs, rejecting duplicates and anything that
// is neither an IP address nor a plain DNS name (no wildcards, schemes or ports).
func splitHosts(hosts []string) ([]net.IP, []string, error) {
	if len(hosts) == 0 || len(hosts) > MaxHosts {
		return nil, nil, fmt.Errorf("certgen: need 1-%d hosts", MaxHosts)
	}
	seen := map[string]bool{}
	var ips []net.IP
	var dns []string
	for _, h := range hosts {
		if seen[h] {
			return nil, nil, fmt.Errorf("certgen: duplicate host %q", h)
		}
		seen[h] = true
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
			continue
		}
		if !validDNSName(h) {
			return nil, nil, fmt.Errorf("certgen: %q is neither an IP address nor a DNS name", h)
		}
		dns = append(dns, h)
	}
	return ips, dns, nil
}

func validDNSName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if !validLabel(l) {
			return false
		}
	}
	return true
}

// validLabel accepts 1-63 of [A-Za-z0-9-], not starting or ending with a hyphen.
func validLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for _, c := range l {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func TestGenerateSelfSigned(t *testing.T) {
	pair, err := Generate(Request{Hosts: []string{"192.0.2.20", "oob.example.test", "2001:db8::1"}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tls.X509KeyPair(pair.CertPEM, pair.KeyPEM); err != nil {
		t.Fatalf("pair does not load: %v", err)
	}
	block, _ := pem.Decode(pair.CertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("key = %T", cert.PublicKey)
	}
	if got := cert.NotAfter.Sub(now); got > MaxValidity || got < MaxValidity-time.Minute {
		t.Fatalf("validity %v", got)
	}
	if !cert.NotBefore.Before(now) {
		t.Fatal("NotBefore must allow small clock skew")
	}
	if len(cert.IPAddresses) != 2 || !cert.IPAddresses[0].Equal(net.ParseIP("192.0.2.20")) ||
		len(cert.DNSNames) != 1 || cert.DNSNames[0] != "oob.example.test" || cert.Subject.CommonName != "192.0.2.20" {
		t.Fatalf("SANs ip=%v dns=%v cn=%q", cert.IPAddresses, cert.DNSNames, cert.Subject.CommonName)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || cert.IsCA {
		t.Fatalf("usage %v ca %v", cert.ExtKeyUsage, cert.IsCA)
	}
	if err := cert.VerifyHostname("oob.example.test"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(pair.KeyPEM), "-----BEGIN PRIVATE KEY-----") {
		t.Fatal("key is not PKCS#8 PEM")
	}
	if len(pair.SHA256) != 64 {
		t.Fatalf("fingerprint %q", pair.SHA256)
	}
}

func TestGenerateRejects(t *testing.T) {
	cases := map[string]Request{
		"no hosts":    {Now: now},
		"bad host":    {Hosts: []string{"bad host"}, Now: now},
		"url":         {Hosts: []string{"https://x.test"}, Now: now},
		"empty label": {Hosts: []string{"a..test"}, Now: now},
		"long label":  {Hosts: []string{strings.Repeat("a", 64) + ".test"}, Now: now},
		"duplicate":   {Hosts: []string{"192.0.2.1", "192.0.2.1"}, Now: now},
		"too long":    {Hosts: []string{"x.test"}, Validity: MaxValidity + time.Hour, Now: now},
		"negative":    {Hosts: []string{"x.test"}, Validity: -time.Hour, Now: now},
		"wildcard":    {Hosts: []string{"*.example.test"}, Now: now},
		"too many":    {Hosts: manyHosts(MaxHosts + 1), Now: now},
	}
	for name, r := range cases {
		if _, err := Generate(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGenerateDefaultsAndShortValidity(t *testing.T) {
	pair, err := Generate(Request{Hosts: []string{"localhost"}, Validity: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pair.CertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(cert.NotAfter); d > 24*time.Hour || d < 23*time.Hour {
		t.Fatalf("validity %v", d)
	}
}

func manyHosts(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "h" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + ".test"
	}
	return out
}

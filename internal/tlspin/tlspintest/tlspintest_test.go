package tlspintest

import (
	"testing"
)

func TestSelfSignedAndIssued(t *testing.T) {
	s := SelfSigned(t)
	if s.CA != nil || len(s.TLS().Certificate) != 1 || len(s.SPKIs()) != 1 {
		t.Fatalf("self-signed: %+v", s)
	}
	i := Issued(t)
	if i.CA == nil || len(i.TLS().Certificate) != 2 || len(i.LeafOnly().Certificate) != 1 {
		t.Fatal("issued pair has no chain")
	}
	if err := i.Leaf.X509.CheckSignatureFrom(i.CA.X509); err != nil {
		t.Fatalf("leaf not signed by the CA: %v", err)
	}
	if len(i.Leaf.SPKI()) != 64 || i.Leaf.SPKI() == i.CA.SPKI() {
		t.Fatalf("SPKIs %s %s", i.Leaf.SPKI(), i.CA.SPKI())
	}
}

func TestIssuedFor(t *testing.T) {
	p := IssuedFor(t, "logs.example.test", "192.0.2.31")
	if p.Leaf.X509.VerifyHostname("192.0.2.31") != nil || p.Leaf.X509.VerifyHostname("logs.example.test") != nil ||
		p.Leaf.X509.VerifyHostname("127.0.0.1") == nil {
		t.Fatalf("names %v %v", p.Leaf.X509.DNSNames, p.Leaf.X509.IPAddresses)
	}
}

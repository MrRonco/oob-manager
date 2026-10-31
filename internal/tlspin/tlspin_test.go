package tlspin

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"testing"
	"time"

	"oob-manager/internal/tlspin/tlspintest"
)

var errTestMismatch = errors.New("test: pin mismatch")

// testName is what tlspintest certificates are issued for.
const testName = "gelf.example.test"

// handshake runs one TLS handshake between cfg (client) and a server presenting cert.
func handshake(t *testing.T, cert tls.Certificate, cfg *tls.Config) error {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		sc, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer sc.Close()
		srv := tls.Server(sc, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		_ = srv.HandshakeContext(context.Background())
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cc, err := (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	return tls.Client(cc, cfg).HandshakeContext(ctx)
}

func pinOf(t *testing.T, hexPin string) []byte {
	t.Helper()
	p, err := ParseHex(hexPin)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLeafMode(t *testing.T) {
	self := tlspintest.SelfSigned(t)
	if err := handshake(t, self.TLS(), Config(pinOf(t, self.Leaf.SPKI()), Leaf, errTestMismatch)); err != nil {
		t.Fatalf("leaf pin refused: %v", err)
	}
	issued := tlspintest.Issued(t)
	// In leaf mode a pinned CA does not help: only the leaf counts.
	err := handshake(t, issued.TLS(), Config(pinOf(t, issued.CA.SPKI()), Leaf, errTestMismatch))
	if !errors.Is(err, errTestMismatch) {
		t.Fatalf("leaf mode accepted the CA pin: %v", err)
	}
}

func TestAnyInChainMode(t *testing.T) {
	issued := tlspintest.Issued(t)
	for name, pin := range map[string]string{"leaf": issued.Leaf.SPKI(), "issuer": issued.CA.SPKI()} {
		if err := handshake(t, issued.TLS(), IssuerConfig(pinOf(t, pin), testName, errTestMismatch)); err != nil {
			t.Errorf("%s pin refused: %v", name, err)
		}
	}
	// A server that sends only its leaf cannot satisfy an issuer pin.
	if err := handshake(t, issued.LeafOnly(), IssuerConfig(pinOf(t, issued.CA.SPKI()), testName, errTestMismatch)); !errors.Is(err, errTestMismatch) {
		t.Fatalf("issuer pin accepted without the chain: %v", err)
	}
	other := tlspintest.SelfSigned(t)
	if err := handshake(t, issued.TLS(), IssuerConfig(pinOf(t, other.Leaf.SPKI()), testName, errTestMismatch)); !errors.Is(err, errTestMismatch) {
		t.Fatalf("wrong pin accepted: %v", err)
	}
}

func TestFailsClosed(t *testing.T) {
	self := tlspintest.SelfSigned(t)
	for name, pin := range map[string][]byte{"nil": nil, "short": {1, 2, 3}, "zero": make([]byte, 32)} {
		if err := handshake(t, self.TLS(), IssuerConfig(pin, testName, errTestMismatch)); !errors.Is(err, errTestMismatch) {
			t.Errorf("%s pin: %v", name, err)
		}
	}
	// No certificate at all.
	if err := Verify(tls.ConnectionState{}, pinOf(t, self.Leaf.SPKI()), AnyInChain, testName, errTestMismatch); !errors.Is(err, errTestMismatch) {
		t.Fatalf("empty chain: %v", err)
	}
	// A nil mismatch error still fails.
	if err := Verify(tls.ConnectionState{}, nil, Leaf, "", nil); err == nil {
		t.Fatal("nil mismatch error accepted the handshake")
	}
}

func TestConfigIsFresh(t *testing.T) {
	pin := pinOf(t, tlspintest.SelfSigned(t).Leaf.SPKI())
	a, b := Config(pin, Leaf, errTestMismatch), Config(pin, Leaf, errTestMismatch)
	if a == b || a.MinVersion != tls.VersionTLS12 || !a.InsecureSkipVerify || a.VerifyConnection == nil {
		t.Fatalf("config %+v", a)
	}
	pin[0] ^= 0xff // the caller's slice is copied
	if err := handshake(t, tlspintest.SelfSigned(t).TLS(), a); !errors.Is(err, errTestMismatch) {
		t.Fatalf("other cert: %v", err)
	}
}

func TestParseHex(t *testing.T) {
	good := hex.EncodeToString(make([]byte, 32))
	if p, err := ParseHex(good); err != nil || len(p) != 32 {
		t.Fatalf("%v %v", p, err)
	}
	for _, bad := range []string{"", "zz", good[:62], good + "00", "AB" + good[2:]} {
		if _, err := ParseHex(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	c := tlspintest.SelfSigned(t)
	if Hex(c.Leaf.X509) != c.Leaf.SPKI() {
		t.Fatal("Hex differs from the SPKI")
	}
}

// TestIssuerPinNeedsASignedLeaf: a CA certificate is public, so an impostor can send
// it after its own leaf. An issuer pin only holds when the leaf really chains to the
// pinned CA (signature and validity verified); the leaf's key is proven by the handshake.
func TestIssuerPinNeedsASignedLeaf(t *testing.T) {
	genuine := tlspintest.Issued(t)
	impostor := tlspintest.SelfSigned(t)
	forged := tls.Certificate{Certificate: [][]byte{impostor.Leaf.X509.Raw, genuine.CA.X509.Raw}, PrivateKey: impostor.Leaf.Key}
	err := handshake(t, forged, IssuerConfig(pinOf(t, genuine.CA.SPKI()), testName, errTestMismatch))
	if !errors.Is(err, errTestMismatch) {
		t.Fatalf("an impostor leaf followed by the real CA certificate was accepted: %v", err)
	}
	// The real leaf from a different CA with the same subject does not chain either.
	other := tlspintest.Issued(t)
	mixed := tls.Certificate{Certificate: [][]byte{other.Leaf.X509.Raw, genuine.CA.X509.Raw}, PrivateKey: other.Leaf.Key}
	if err := handshake(t, mixed, IssuerConfig(pinOf(t, genuine.CA.SPKI()), testName, errTestMismatch)); !errors.Is(err, errTestMismatch) {
		t.Fatalf("a leaf of another CA was accepted: %v", err)
	}
}

// TestIssuerPinChecksTheName: a CA signs certificates for many names (a public CA signs
// anyone's). An issuer pin accepts only a leaf valid for the log server's own name or IP,
// so a certificate the same CA issued for another name is refused; an empty name refuses
// every issuer match. A leaf pin is not name-checked (it is that exact key).
func TestIssuerPinChecksTheName(t *testing.T) {
	issued := tlspintest.Issued(t) // leaf for gelf.example.test and 127.0.0.1
	pin := pinOf(t, issued.CA.SPKI())
	for name, ok := range map[string]bool{"gelf.example.test": true, "127.0.0.1": true, "attacker.example.test": false,
		"192.0.2.9": false, "": false} {
		err := handshake(t, issued.TLS(), IssuerConfig(pin, name, errTestMismatch))
		if ok != (err == nil) {
			t.Errorf("name %q: %v", name, err)
		}
	}
	if err := handshake(t, issued.TLS(), Config(pin, AnyInChain, errTestMismatch)); !errors.Is(err, errTestMismatch) {
		t.Fatalf("Config(AnyInChain) without a name accepted an issuer match: %v", err)
	}
	if err := handshake(t, issued.TLS(), IssuerConfig(pinOf(t, issued.Leaf.SPKI()), "other.example.test", errTestMismatch)); err != nil {
		t.Fatalf("a leaf pin was name-checked: %v", err)
	}
}

// TestIssuerPinExpiredLeaf: the right CA and name but an expired leaf is refused and
// reported as an expiry (ErrExpired wrapping the mismatch), not as an impostor.
func TestIssuerPinExpiredLeaf(t *testing.T) {
	p := tlspintest.IssuedExpired(t)
	err := handshake(t, p.TLS(), IssuerConfig(pinOf(t, p.CA.SPKI()), testName, errTestMismatch))
	if !errors.Is(err, ErrExpired) || !errors.Is(err, errTestMismatch) {
		t.Fatalf("expired leaf: %v", err)
	}
	other := tlspintest.SelfSigned(t)
	if err := handshake(t, other.TLS(), IssuerConfig(pinOf(t, p.CA.SPKI()), testName, errTestMismatch)); errors.Is(err, ErrExpired) {
		t.Fatal("a wrong certificate reported as expired")
	}
}

package tofu

import (
	"context"
	"crypto/tls"
	"io"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/tlspin/tlspintest"
)

// tlsListener is a raw TLS server (a GELF TLS input): it completes handshakes and
// counts every application byte it receives. sni records the last ServerName seen.
type tlsListener struct {
	addr  string
	mu    sync.Mutex
	bytes int
	sni   string
}

func newTLSListener(t *testing.T, cert tls.Certificate) *tlsListener {
	t.Helper()
	l := &tlsListener{}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			l.mu.Lock()
			l.sni = h.ServerName
			l.mu.Unlock()
			return nil, nil
		}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	l.addr = ln.Addr().String()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer c.Close()
				n, _ := io.Copy(io.Discard, c)
				l.mu.Lock()
				l.bytes += int(n)
				l.mu.Unlock()
			}()
		}
	}()
	return l
}

func (l *tlsListener) seen() (int, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.bytes, l.sni
}

// TestFetchTLSChain: a server that sends its chain yields the leaf and the issuer's
// SPKI; one that sends only a self-signed leaf yields no chain. No application byte is
// ever sent (the GELF port receives nothing but the handshake).
func TestFetchTLSChain(t *testing.T) {
	issued := tlspintest.Issued(t)
	srv := newTLSListener(t, issued.TLS())
	info, err := FetchTLS(context.Background(), addrPort(t, srv.addr), Options{ServerName: "gelf.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if info.SPKI != issued.Leaf.SPKI() || len(info.Chain) != 1 || info.Chain[0].SPKI != issued.CA.SPKI() {
		t.Fatalf("leaf %s chain %+v", info.SPKI, info.Chain)
	}
	if info.SelfIssued || !info.Chain[0].SelfIssued || info.Chain[0].Subject != "CN=Test log CA" {
		t.Fatalf("self-issued flags %+v", info)
	}
	if !info.IssuerVerified {
		t.Fatal("the issuer was not verified")
	}
	if got := info.Recommended(); got != issued.CA.SPKI() {
		t.Fatalf("recommended %s, want the issuer", got)
	}

	self := tlspintest.SelfSigned(t)
	srv2 := newTLSListener(t, self.TLS())
	info2, err := FetchTLS(context.Background(), addrPort(t, srv2.addr), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(info2.Chain) != 0 || !info2.SelfIssued || info2.Recommended() != self.Leaf.SPKI() {
		t.Fatalf("self-signed %+v", info2)
	}
	time.Sleep(50 * time.Millisecond) // the servers count what they read when the fetch closes
	for _, l := range []*tlsListener{srv, srv2} {
		if n, _ := l.seen(); n != 0 {
			t.Fatalf("the server received %d application bytes", n)
		}
	}
	if _, sni := srv.seen(); sni != "gelf.example.test" {
		t.Fatalf("SNI %q", sni)
	}
}

// TestChainIsCapped: at most maxChain certificates after the leaf are reported.
func TestChainIsCapped(t *testing.T) {
	issued := tlspintest.Issued(t)
	der := [][]byte{issued.Leaf.X509.Raw}
	for range maxChain + 3 {
		der = append(der, issued.CA.X509.Raw)
	}
	srv := newTLSListener(t, tls.Certificate{Certificate: der, PrivateKey: issued.Leaf.Key})
	info, err := FetchTLS(context.Background(), addrPort(t, srv.addr), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Chain) != maxChain {
		t.Fatalf("chain %d, want %d", len(info.Chain), maxChain)
	}
}

// TestFetchTLSUnrelatedChain: a CA certificate sent after a leaf it did not issue is
// reported but not verified, so the leaf is recommended (an issuer pin would not hold).
func TestFetchTLSUnrelatedChain(t *testing.T) {
	self := tlspintest.SelfSigned(t)
	ca := tlspintest.Issued(t).CA
	srv := newTLSListener(t, tls.Certificate{Certificate: [][]byte{self.Leaf.X509.Raw, ca.X509.Raw}, PrivateKey: self.Leaf.Key})
	info, err := FetchTLS(context.Background(), addrPort(t, srv.addr), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if info.IssuerProblem != IssuerUnrelated {
		t.Fatalf("problem %q", info.IssuerProblem)
	}
	if len(info.Chain) != 1 || info.IssuerVerified || info.Recommended() != self.Leaf.SPKI() {
		t.Fatalf("unrelated chain %+v", info)
	}
}

// TestFetchTLSIssuerName: an issuer pin is offered only when the leaf is valid for the
// name the console will check (the server name, else the IP dialled); a test CA is not
// publicly trusted.
func TestFetchTLSIssuerName(t *testing.T) {
	issued := tlspintest.Issued(t) // leaf: gelf.example.test and 127.0.0.1
	srv := newTLSListener(t, issued.TLS())
	byIP, err := FetchTLS(context.Background(), addrPort(t, srv.addr), Options{})
	if err != nil || !byIP.IssuerVerified || byIP.IssuerPublic || byIP.Recommended() != issued.CA.SPKI() {
		t.Fatalf("by IP %+v %v", byIP, err)
	}
	wrong, err := FetchTLS(context.Background(), addrPort(t, srv.addr), Options{ServerName: "logs.other.test"})
	if err != nil || wrong.IssuerVerified || wrong.IssuerProblem != IssuerWrongName || wrong.Recommended() != issued.Leaf.SPKI() {
		t.Fatalf("wrong name %+v %v", wrong, err)
	}
}

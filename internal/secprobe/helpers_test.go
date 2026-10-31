package secprobe

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

// certSpec describes a test certificate.
type certSpec struct {
	key      crypto.Signer
	subject  pkix.Name
	notAfter time.Time
	sigAlg   x509.SignatureAlgorithm
	issuer   *x509.Certificate // nil: self-signed
	issuerK  crypto.Signer
}

func ecKey(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func rsaKey(t *testing.T, bits int) crypto.Signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits) //nolint:gosec // G403: small keys on purpose (weak-key tests)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func makeCert(t *testing.T, c certSpec) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	if c.notAfter.IsZero() {
		c.notAfter = time.Now().Add(365 * 24 * time.Hour)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: c.subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: c.notAfter, SignatureAlgorithm: c.sigAlg,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	parent, signer := tmpl, c.key
	if c.issuer != nil {
		parent, signer = c.issuer, c.issuerK
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, c.key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: c.key, Leaf: leaf}, leaf
}

func pinOf(leaf *x509.Certificate) []byte {
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return sum[:]
}

// tlsServer accepts TLS connections with cfg and counts handshakes and any application
// byte a client sends (a probe must send none).
type tlsServer struct {
	addr       netip.AddrPort
	conns      atomic.Int32
	handshakes atomic.Int32
	appBytes   atomic.Int64
	wg         sync.WaitGroup
}

func newTLSServer(t *testing.T, cfg *tls.Config) *tlsServer {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &tlsServer{addr: netip.MustParseAddrPort(ln.Addr().String())}
	t.Cleanup(func() { _ = ln.Close(); s.wg.Wait() })
	s.wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			s.wg.Go(func() { s.serve(tls.Server(c, cfg)) })
		}
	})
	return s
}

func (s *tlsServer) serve(c *tls.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c.HandshakeContext(ctx) != nil {
		return
	}
	s.handshakes.Add(1)
	n, _ := io.Copy(io.Discard, c)
	s.appBytes.Add(n)
}

// closedAddr is an address with nothing listening.
func closedAddr(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddrPort(ln.Addr().String())
	_ = ln.Close()
	return a
}

// rawServer runs fn for each accepted connection (plain TCP).
func rawServer(t *testing.T, fn func(net.Conn)) netip.AddrPort {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer c.Close()
				fn(c)
			})
		}
	})
	return netip.MustParseAddrPort(ln.Addr().String())
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

var errDialRefused = errors.New("refused by test dialer")

// fastOpts are the default options with the handshake spacing cut to a millisecond.
func fastOpts() Options { return Options{ProbeGap: time.Millisecond} }

// variantFacts names the version and suite facts of a probe.
func variantFacts(p bmc.TLSProbe) map[string]bmc.Fact[bool] {
	return map[string]bmc.Fact[bool]{"TLS10": p.TLS10, "TLS11": p.TLS11, "TLS12": p.TLS12, "TLS13": p.TLS13,
		"WeakCipher": p.WeakCipher, "RSAKeyExchange": p.RSAKeyExchange, "ForwardSecrecy": p.ForwardSecrecy}
}

// resettingServer completes a TLS handshake on its first n connections and resets every
// later one without a byte (a BMC web server that drops rapid connections).
func resettingServer(t *testing.T, cfg *tls.Config, n int32) (netip.AddrPort, *atomic.Int32) {
	t.Helper()
	var conns atomic.Int32
	addr := rawServer(t, func(c net.Conn) {
		if conns.Add(1) > n {
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0) // the deferred Close sends RST
			}
			return
		}
		s := tls.Server(c, cfg)
		_ = s.SetDeadline(time.Now().Add(5 * time.Second))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if s.HandshakeContext(ctx) == nil {
			_, _ = io.Copy(io.Discard, s)
		}
	})
	return addr, &conns
}

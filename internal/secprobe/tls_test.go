package secprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/textclean"
)

func modernServer(t *testing.T) (*tlsServer, *x509.Certificate) {
	t.Helper()
	cert, leaf := makeCert(t, certSpec{key: ecKey(t), subject: pkix.Name{CommonName: "bmc.example", Organization: []string{"Example"}}})
	return newTLSServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}), leaf
}

func TestScanTLSModernServer(t *testing.T) {
	srv, leaf := modernServer(t)
	p := ScanTLS(testCtx(t), TLSTarget{Addr: srv.addr, Pin: pinOf(leaf)}, fastOpts())
	if !p.Read.OK() || !p.PinMatch || !p.Usable() || p.Port != int(srv.addr.Port()) {
		t.Fatalf("probe %+v", p)
	}
	if p.Negotiated != "TLS 1.3" || p.Cipher == "" {
		t.Fatalf("identity handshake %q %q", p.Negotiated, p.Cipher)
	}
	want := map[string]struct {
		f    bmc.Fact[bool]
		want bool
	}{
		"TLS10": {p.TLS10, false}, "TLS11": {p.TLS11, false}, "TLS12": {p.TLS12, true}, "TLS13": {p.TLS13, true},
		"WeakCipher": {p.WeakCipher, false}, "RSAKeyExchange": {p.RSAKeyExchange, false}, "ForwardSecrecy": {p.ForwardSecrecy, true},
	}
	for name, c := range want {
		if !c.f.Known || c.f.Value != c.want || c.f.Source == "" {
			t.Errorf("%s = %+v, want known %v", name, c.f, c.want)
		}
	}
	if p.Cert.KeyType != "ECDSA" || p.Cert.KeyBits != 256 || !p.Cert.SelfSigned || p.Cert.SubjectCN != "bmc.example" ||
		p.Cert.SubjectOrg != "Example" || len(p.Cert.SHA256) != 64 || p.Cert.Signature != "ECDSA-SHA256" {
		t.Fatalf("cert %+v", p.Cert)
	}
	if n := srv.appBytes.Load(); n != 0 {
		t.Fatalf("a TLS probe must send no application data, sent %d bytes", n)
	}
	if n := srv.conns.Load(); n != 8 {
		t.Fatalf("connections = %d, want the identity handshake plus 7 probes", n)
	}
}

func TestScanTLSLegacyServer(t *testing.T) {
	cert, leaf := makeCert(t, certSpec{key: rsaKey(t, 2048), subject: pkix.Name{CommonName: "old"}, sigAlg: x509.SHA256WithRSA})
	var all []uint16
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		all = append(all, s.ID)
	}
	srv := newTLSServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10, //nolint:gosec // G402: a legacy server under test
		CipherSuites: all})
	p := ScanTLS(testCtx(t), TLSTarget{Addr: srv.addr, Pin: pinOf(leaf)}, fastOpts())
	if !p.TLS10.Value || !p.TLS11.Value || !p.WeakCipher.Value || !p.RSAKeyExchange.Value || !p.ForwardSecrecy.Value {
		t.Fatalf("legacy server %+v", p)
	}
	if p.Cert.KeyType != "RSA" || p.Cert.KeyBits != 2048 || p.Cert.Signature != "SHA256-RSA" {
		t.Fatalf("cert %+v", p.Cert)
	}
}

func TestScanTLSRSAOnlyServer(t *testing.T) {
	cert, leaf := makeCert(t, certSpec{key: rsaKey(t, 2048), subject: pkix.Name{CommonName: "vnc"}})
	srv := newTLSServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384}}) //nolint:gosec // G402: an iDRAC8-like VNC port under test
	if p := ScanTLS(testCtx(t), TLSTarget{Addr: srv.addr, Pin: pinOf(leaf)}, fastOpts()); p.Read.OK() {
		t.Fatalf("without RSA key exchange the identity handshake must fail: %+v", p.Read)
	}
	p := ScanTLS(testCtx(t), TLSTarget{Addr: srv.addr, Pin: pinOf(leaf), RSAKeyExchange: true}, fastOpts())
	if !p.Usable() || p.ForwardSecrecy.Value || !p.ForwardSecrecy.Known || !p.RSAKeyExchange.Value || p.TLS13.Value {
		t.Fatalf("RSA-only port %+v", p)
	}
}

func TestScanTLSPinMismatchStops(t *testing.T) {
	srv, _ := modernServer(t)
	p := ScanTLS(testCtx(t), TLSTarget{Addr: srv.addr, Pin: make([]byte, 32)}, fastOpts())
	if !p.Read.OK() || p.PinMatch || p.Usable() || p.TLS10.Known {
		t.Fatalf("mismatch %+v", p)
	}
	if n := srv.conns.Load(); n != 1 {
		t.Fatalf("a host that is not the pinned BMC gets one handshake, not %d", n)
	}
}

func TestScanTLSFailures(t *testing.T) {
	if p := ScanTLS(testCtx(t), TLSTarget{Addr: closedAddr(t), Pin: make([]byte, 32)}, fastOpts()); p.Read.State != bmc.ReadFailed ||
		p.Read.Class != bmc.ClassUnreachable {
		t.Fatalf("closed port %+v", p.Read)
	}
	notTLS := rawServer(t, func(c net.Conn) { _, _ = c.Write([]byte("SSH-2.0-not-tls\r\n")) })
	if p := ScanTLS(testCtx(t), TLSTarget{Addr: notTLS, Pin: make([]byte, 32)}, fastOpts()); p.Read.State != bmc.ReadFailed ||
		p.Read.Class != bmc.ClassProtocol {
		t.Fatalf("not TLS %+v", p.Read)
	}
	silent := rawServer(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	p := ScanTLS(testCtx(t), TLSTarget{Addr: silent, Pin: make([]byte, 32)}, Options{HandshakeTimeout: 200 * time.Millisecond, ProbeGap: time.Millisecond})
	if p.Read.State != bmc.ReadFailed || p.Read.Class != bmc.ClassTimeout {
		t.Fatalf("silent %+v", p.Read)
	}
}

func TestScanTLSDialerIsUsed(t *testing.T) {
	srv, leaf := modernServer(t)
	var dialed []string
	o := Options{ProbeGap: time.Millisecond, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		if len(dialed) > 2 {
			return nil, errDialRefused
		}
		return (&net.Dialer{}).DialContext(ctx, network, srv.addr.String())
	}}
	p := ScanTLS(testCtx(t), TLSTarget{Addr: srv.addr, Pin: pinOf(leaf)}, o)
	if !p.Usable() || !p.TLS10.Known || p.TLS11.Known {
		t.Fatalf("a probe whose dial fails is unknown, not refused: %+v", p)
	}
	for _, a := range dialed {
		if a != srv.addr.String() {
			t.Fatalf("dialled %s", a)
		}
	}
}

func TestCertFactsSanitizedAndSelfSigned(t *testing.T) {
	caKey := ecKey(t)
	_, caLeaf := makeCert(t, certSpec{key: caKey, subject: pkix.Name{CommonName: "Lab CA"}})
	_, leaf := makeCert(t, certSpec{key: rsaKey(t, 2048), subject: pkix.Name{CommonName: "bmc\u202e\x07evil",
		OrganizationalUnit: []string{"Remote Access Group"}}, issuer: caLeaf, issuerK: caKey})
	f := certFacts(leaf)
	if f.SelfSigned || f.SubjectCN != "bmcevil" || f.SubjectOrgUnit != "Remote Access Group" || !strings.Contains(f.Issuer, "Lab CA") {
		t.Fatalf("facts %+v", f)
	}
	long := strings.Repeat("x", 500)
	if got := textclean.Clean(long, 200); len(got) != 200 {
		t.Fatalf("cap %d", len(got))
	}
}

// TestScanTLSResetIsNotARefusal: a server that resets every connection after the first
// leaves every variant unknown (and says why), never "refused": a refusal is a TLS alert.
func TestScanTLSResetIsNotARefusal(t *testing.T) {
	cert, leaf := makeCert(t, certSpec{key: ecKey(t), subject: pkix.Name{CommonName: "bmc"}})
	addr, _ := resettingServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, 1)
	p := ScanTLS(testCtx(t), TLSTarget{Addr: addr, Pin: pinOf(leaf)}, fastOpts())
	if !p.Usable() {
		t.Fatalf("identity handshake %+v", p.Read)
	}
	for name, f := range variantFacts(p) {
		if f.Known {
			t.Errorf("%s = %+v, want unknown: a reset says nothing about what the port accepts", name, f)
		}
	}
	if !strings.Contains(p.Partial, "reset") {
		t.Fatalf("Partial = %q, want the reason the variants are unknown", p.Partial)
	}
}

func TestRefusedByPeer(t *testing.T) {
	cases := map[string]struct {
		err  error
		want bool
	}{
		"remote alert":          {&net.OpError{Op: "remote error", Err: errors.New("tls: protocol version not supported")}, true},
		"handshake failure":     {&net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}, true},
		"insufficient security": {&net.OpError{Op: "remote error", Err: errors.New("tls: insufficient security level")}, true},
		"internal error":        {&net.OpError{Op: "remote error", Err: errors.New("tls: internal error")}, false},
		"bad certificate":       {&net.OpError{Op: "remote error", Err: errors.New("tls: bad certificate")}, false},
		"alert error":           {tls.AlertError(70), true},
		"alert handshake":       {tls.AlertError(40), true},
		"alert insufficient":    {tls.AlertError(71), true},
		"alert internal":        {tls.AlertError(80), false},
		"eof":                   {io.EOF, false},
		"reset":                 {&net.OpError{Op: "read", Err: syscall.ECONNRESET}, false},
		"timeout":               {context.DeadlineExceeded, false},
		"pin":                   {bmc.ErrPinMismatch, false},
		"dial":                  {&dialFailed{err: errDialRefused}, false},
		"nil":                   {nil, false},
	}
	for name, c := range cases {
		if got := refusedByPeer(c.err); got != c.want {
			t.Errorf("%s: refusedByPeer = %v, want %v", name, got, c.want)
		}
	}
}

// TestScanTLSInconsistentServerIsUnknown: a port that refuses, when offered alone, the
// very TLS version it negotiated moments before is not answering consistently; no
// variant is trusted.
func TestScanTLSInconsistentServerIsUnknown(t *testing.T) {
	cert, leaf := makeCert(t, certSpec{key: ecKey(t), subject: pkix.Name{CommonName: "bmc"}})
	var conns atomic.Int32
	base := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		if conns.Add(1) == 5 { // the identity handshake, then TLS 1.0, 1.1, 1.2 alone, then TLS 1.3 alone
			c := base.Clone()
			c.MaxVersion = tls.VersionTLS12
			return c, nil
		}
		return nil, nil
	}
	srv := newTLSServer(t, base)
	p := ScanTLS(testCtx(t), TLSTarget{Addr: srv.addr, Pin: pinOf(leaf)}, fastOpts())
	if !p.Usable() || p.Negotiated != "TLS 1.3" {
		t.Fatalf("identity %+v", p)
	}
	for name, f := range variantFacts(p) {
		if f.Known {
			t.Errorf("%s = %+v, want unknown", name, f)
		}
	}
	if !strings.Contains(p.Partial, "refused the TLS version") {
		t.Fatalf("Partial = %q", p.Partial)
	}
}

// TestScanTLSAbortsForTheConsole: the abort callback is asked before each variant; once
// it answers with a reason the remaining variants stay unknown and the reason is kept.
func TestScanTLSAbortsForTheConsole(t *testing.T) {
	srv, leaf := modernServer(t)
	const why = "a graphical console session was opened"
	var asked atomic.Int32
	abort := func() string {
		if asked.Add(1) > 2 {
			return why
		}
		return ""
	}
	p := ScanTLS(testCtx(t), TLSTarget{Addr: srv.addr, Pin: pinOf(leaf), Abort: abort}, fastOpts())
	if !p.Usable() || !p.TLS10.Known || !p.TLS11.Known || p.TLS12.Known || p.TLS13.Known || p.WeakCipher.Known ||
		p.RSAKeyExchange.Known || p.ForwardSecrecy.Known {
		t.Fatalf("probe %+v", p)
	}
	if p.Partial != why || srv.conns.Load() != 3 || asked.Load() != 3 {
		t.Fatalf("partial %q connections %d asked %d", p.Partial, srv.conns.Load(), asked.Load())
	}
}

// TestScanTLSIdentityOnly: one handshake, the certificate, nothing else (the VNC port).
func TestScanTLSIdentityOnly(t *testing.T) {
	srv, leaf := modernServer(t)
	p := ScanTLS(testCtx(t), TLSTarget{Addr: srv.addr, Pin: pinOf(leaf), IdentityOnly: true}, fastOpts())
	if !p.Usable() || p.Cert.SubjectCN != "bmc.example" || srv.conns.Load() != 1 || p.TLS12.Known || p.Partial == "" {
		t.Fatalf("probe %+v connections %d", p, srv.conns.Load())
	}
}

// TestScanTLSSpacesTheHandshakes: the variants are not fired back to back.
func TestScanTLSSpacesTheHandshakes(t *testing.T) {
	srv, leaf := modernServer(t)
	const gap = 40 * time.Millisecond
	start := time.Now()
	p := ScanTLS(testCtx(t), TLSTarget{Addr: srv.addr, Pin: pinOf(leaf)}, Options{ProbeGap: gap})
	if took := time.Since(start); !p.Usable() || took < 7*gap {
		t.Fatalf("7 variants took %v, want at least %v between handshakes", took, 7*gap)
	}
}

// TestHandshakeNilPinFailsClosed: a probe handshake without a pin matches nothing.
func TestHandshakeNilPinFailsClosed(t *testing.T) {
	srv, _ := modernServer(t)
	_, _, err := handshake(testCtx(t), srv.addr, &tls.Config{MinVersion: tls.VersionTLS12}, nil, fastOpts().withDefaults())
	if !errors.Is(err, bmc.ErrPinMismatch) {
		t.Fatalf("nil pin: %v, want ErrPinMismatch", err)
	}
}

// TestScanTLSRefusedIsAClosedPort: a connection refused is a known closed port (Refused),
// told apart from a port that cannot be reached.
func TestScanTLSRefusedIsAClosedPort(t *testing.T) {
	p := ScanTLS(testCtx(t), TLSTarget{Addr: closedAddr(t), Pin: make([]byte, 32)}, fastOpts())
	if p.Read.State != bmc.ReadFailed || p.Read.Class != bmc.ClassUnreachable || !p.Refused {
		t.Fatalf("closed port %+v", p)
	}
	o := Options{ProbeGap: time.Millisecond, Dial: func(context.Context, string, string) (net.Conn, error) { return nil, errDialRefused }}
	if p := ScanTLS(testCtx(t), TLSTarget{Addr: closedAddr(t), Pin: make([]byte, 32)}, o); p.Refused {
		t.Fatalf("a dialer error is not a refusal: %+v", p)
	}
}

// TestScanTLSInternalErrorIsNotARefusal: a server that answers a hello it cannot serve
// with internal_error (not protocol_version) leaves the variant unknown; only
// protocol_version, handshake_failure and insufficient_security mean "refused".
func TestScanTLSInternalErrorIsNotARefusal(t *testing.T) {
	cert, leaf := makeCert(t, certSpec{key: ecKey(t), subject: pkix.Name{CommonName: "bmc"}})
	base := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if slices.Max(hello.SupportedVersions) < tls.VersionTLS12 {
			return nil, errors.New("cannot serve this client") // Go answers with alert internal_error
		}
		return nil, nil
	}
	srv := newTLSServer(t, base)
	p := ScanTLS(testCtx(t), TLSTarget{Addr: srv.addr, Pin: pinOf(leaf)}, fastOpts())
	if !p.Usable() || p.TLS10.Known || p.TLS11.Known || !p.TLS12.Known || !p.TLS12.Value || !p.TLS13.Known || !p.TLS13.Value {
		t.Fatalf("probe %+v", p)
	}
}

// TestScanTLSResetWhileConnectingIsReached: a port that resets a connection before the
// client has finished connecting (connect: connection reset by peer; seen on a loaded
// host, where the peer's RST lands before the dial returns) was reached and gave no TLS
// answer, exactly like a reset after the connect: every variant is unknown, and Partial
// says why. Only a connection that could not be made at all is "not reached".
func TestScanTLSResetWhileConnectingIsReached(t *testing.T) {
	cert, leaf := makeCert(t, certSpec{key: ecKey(t), subject: pkix.Name{CommonName: "bmc"}})
	addr, _ := resettingServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, 1)
	var dials atomic.Int32
	o := fastOpts()
	o.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if dials.Add(1) > 1 {
			return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", syscall.ECONNRESET)}
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	p := ScanTLS(testCtx(t), TLSTarget{Addr: addr, Pin: pinOf(leaf)}, o)
	if !p.Usable() {
		t.Fatalf("identity handshake %+v", p.Read)
	}
	for name, f := range variantFacts(p) {
		if f.Known {
			t.Errorf("%s = %+v, want unknown", name, f)
		}
	}
	if p.Partial != PartialNoAnswer {
		t.Fatalf("Partial = %q, want %q", p.Partial, PartialNoAnswer)
	}
}

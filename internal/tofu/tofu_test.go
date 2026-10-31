package tofu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"oob-manager/internal/bmc/bmcssh/sshtest"
	"oob-manager/internal/console/rfbtest"
)

// quick are short bounds so the timeout cases finish fast.
var quick = Options{DialTimeout: 300 * time.Millisecond, HandshakeTimeout: 300 * time.Millisecond}

func addrPort(t *testing.T, hostport string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(hostport)
	if err != nil {
		t.Fatal(err)
	}
	return ap
}

// TestFetchTLSNoHTTPBytes: the fetch is handshake-only. The HTTPS server sees zero HTTP
// requests, so no redirect can be followed and no credential can leave the app.
func TestFetchTLSNoHTTPBytes(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	info, err := FetchTLS(context.Background(), addrPort(t, srv.Listener.Addr().String()), quick)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	if info.SPKI != hex.EncodeToString(sum[:]) {
		t.Fatalf("spki = %s", info.SPKI)
	}
	if info.NotAfter.IsZero() || len(info.SANs) == 0 || info.Grouped() == "" || len(strings.Fields(info.Grouped())) != 16 {
		t.Fatalf("info = %+v", info)
	}
	time.Sleep(50 * time.Millisecond)
	if n := hits.Load(); n != 0 {
		t.Fatalf("server saw %d HTTP requests", n)
	}
}

func TestFetchTLSFailures(t *testing.T) {
	// Blackhole: accepts, never answers.
	hole, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hole.Close()
	go func() {
		for {
			c, aerr := hole.Accept()
			if aerr != nil {
				return
			}
			defer c.Close()
		}
	}()
	assertClass(t, "blackhole", ClassTimeout, fetchTLS(t, hole.Addr().String()))
	// Plain TCP that answers with HTTP: not TLS.
	plain := httptest.NewServer(http.NotFoundHandler())
	defer plain.Close()
	assertClass(t, "plain", ClassNotTLS, fetchTLS(t, plain.Listener.Addr().String()))
	// Nothing listening.
	closed, _ := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	addr := closed.Addr().String()
	_ = closed.Close()
	assertClass(t, "refused", ClassUnreachable, fetchTLS(t, addr))
}

func fetchTLS(t *testing.T, hostport string) error {
	t.Helper()
	_, err := FetchTLS(context.Background(), addrPort(t, hostport), quick)
	return err
}

func assertClass(t *testing.T, name string, want Class, err error) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Class != want {
		t.Errorf("%s: err = %v, want class %s", name, err, want)
	}
}

// TestFetchTLSRSAKexVNC: an iDRAC8 VNC port only offers RSA key exchange; the option
// that allows it fetches the certificate, the default refuses the handshake.
func TestFetchTLSRSAKexVNC(t *testing.T) {
	vnc := rfbtest.New(t, rfbtest.Options{TLS: true, RSAKeyExchangeOnly: true})
	ap := addrPort(t, vnc.Addr())
	if _, err := FetchTLS(context.Background(), ap, quick); err == nil {
		t.Fatal("ECDHE-only fetch completed against an RSA-kex-only server")
	}
	o := quick
	o.RSAKeyExchange = true
	info, err := FetchTLS(context.Background(), ap, o)
	if err != nil || info.SPKI != vnc.PinSHA256() {
		t.Fatalf("rsa kex fetch: %v %s vs %s", err, info.SPKI, vnc.PinSHA256())
	}
}

// TestFetchSSHHostKey: the host key is read and the connection dropped before any
// authentication, so no password is ever offered and the BMC logs no login attempt.
func TestFetchSSHHostKey(t *testing.T) {
	for name, o := range map[string]sshtest.Options{"ed25519": {}, "legacy rsa": {Legacy: true}} {
		srv := sshtest.New(t, o)
		key, err := FetchSSHHostKey(context.Background(), addrPort(t, srv.Addr()), SSHOptions{Options: quick, Legacy: o.Legacy})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if key.Line != srv.HostKeyLine() || !strings.HasPrefix(key.Fingerprint, "SHA256:") || key.Type == "" {
			t.Fatalf("%s: key = %+v (want %s)", name, key, srv.HostKeyLine())
		}
		if n := srv.AuthAttempts(); n != 0 {
			t.Fatalf("%s: %d auth attempts", name, n)
		}
	}
	// A legacy-only server without the legacy option: no common algorithm.
	legacy := sshtest.New(t, sshtest.Options{Legacy: true})
	_, err := FetchSSHHostKey(context.Background(), addrPort(t, legacy.Addr()), SSHOptions{Options: quick})
	assertClass(t, "legacy without quirk", ClassNotSSH, err)
	plain := httptest.NewServer(http.NotFoundHandler())
	defer plain.Close()
	_, err = FetchSSHHostKey(context.Background(), addrPort(t, plain.Listener.Addr().String()), SSHOptions{Options: quick})
	if err == nil {
		t.Fatal("HTTP server gave an SSH host key")
	}
}

// TestDialerIsTheOnlyRoute: with a Dialer set, nothing else is dialled (the e2e harness
// redirects TEST-NET addresses to fakes this way).
func TestDialerIsTheOnlyRoute(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	var dialled atomic.Value
	o := quick
	o.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialled.Store(addr)
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	if _, err := FetchTLS(context.Background(), addrPort(t, "192.0.2.12:443"), o); err != nil {
		t.Fatal(err)
	}
	if got, _ := dialled.Load().(string); got != "192.0.2.12:443" {
		t.Fatalf("dialled %q", got)
	}
}

func TestErrorText(t *testing.T) {
	e := &Error{Class: ClassBadCert}
	if e.Error() == "" || e.Message() == "" {
		t.Fatal("empty")
	}
	for _, c := range []Class{ClassUnreachable, ClassTimeout, ClassNotTLS, ClassBadCert, ClassNotSSH} {
		if (&Error{Class: c}).Message() == "" {
			t.Errorf("%s: no message", c)
		}
	}
}

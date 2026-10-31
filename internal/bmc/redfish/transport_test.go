package redfish

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
)

func TestPinMatchConnects(t *testing.T) {
	s := mockFor(t, idrac9)
	d := driverFor(t, s)
	if _, err := d.Probe(testCtx(t)); err != nil {
		t.Fatalf("Probe with correct pin: %v", err)
	}
}

func TestPinMismatchIsRefusedBeforeAnyRequest(t *testing.T) {
	s := mockFor(t, idrac9)
	cfg := configFor(s)
	cfg.PinSHA256 = strings.Repeat("00", 32)
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Probe(testCtx(t))
	if !errors.Is(err, bmc.ErrPinMismatch) {
		t.Fatalf("want ErrPinMismatch, got %v", err)
	}
	if bmc.Classify(err) != bmc.ClassTLS {
		t.Fatalf("class %q", bmc.Classify(err))
	}
	if n := len(s.Requests()); n != 0 {
		t.Fatalf("server saw %d HTTP requests; credentials may have been sent", n)
	}
}

func TestSPKIPinMatchesMock(t *testing.T) {
	s := mockFor(t, idrac9)
	cert := mustLeaf(t, s)
	if got := SPKIPin(cert); got != s.PinSHA256() {
		t.Fatalf("SPKIPin = %s, want %s", got, s.PinSHA256())
	}
}

func mustLeaf(t *testing.T, s *redfishmock.Server) *x509.Certificate {
	t.Helper()
	host := strings.TrimPrefix(s.URL(), "https://")
	// Test-only raw dial to read the mock certificate; production code pins instead.
	d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // test-only dial to read the mock certificate
	conn, err := d.DialContext(t.Context(), "tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		t.Fatalf("dial returned %T, want *tls.Conn", conn)
	}
	return tc.ConnectionState().PeerCertificates[0]
}

func TestWritesAreRefusedByTransport(t *testing.T) {
	s := mockFor(t, idrac9)
	d := driverFor(t, s)
	for _, m := range []string{http.MethodHead, http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete} {
		req, _ := http.NewRequestWithContext(t.Context(), m, s.URL()+"/redfish/v1/Systems/System.Embedded.1", nil)
		resp, err := d.httpClient.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, bmc.ErrMethodNotAllowed) {
			t.Fatalf("%s: want ErrMethodNotAllowed, got %v", m, err)
		}
	}
	if len(s.Requests()) != 0 {
		t.Fatalf("write reached the server: %+v", s.Requests())
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	s := mockFor(t, idrac9)
	d := driverFor(t, s)
	err := d.httpClient.CheckRedirect(&http.Request{}, nil)
	if !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect = %v", err)
	}
}

func TestResponseSizeCap(t *testing.T) {
	s := mockFor(t, idrac8)
	cfg := configFor(s)
	cfg.MaxBodyBytes = 4096 // root (1.6 KB) fits, the System resource (7.7 KB) does not
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Probe(testCtx(t))
	if !errors.Is(err, bmc.ErrResponseTooLarge) {
		t.Fatalf("want ErrResponseTooLarge, got %v", err)
	}
}

func TestPerRequestTimeout(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithDelay("*", 3*time.Second))
	cfg := configFor(s)
	cfg.Timeout = 150 * time.Millisecond
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = d.Probe(testCtx(t))
	if !errors.Is(err, bmc.ErrTimeout) {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("timeout not enforced: %v", el)
	}
}

func TestParentContextDeadline(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithDelay("*", 3*time.Second))
	d := driverFor(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := d.Snapshot(ctx)
	if !errors.Is(err, bmc.ErrTimeout) {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
}

func TestAuthFailure(t *testing.T) {
	s := mockFor(t, idrac9)
	cfg := configFor(s)
	cfg.Password = "wrong"
	d, _ := New(cfg)
	_, err := d.Probe(testCtx(t))
	if !errors.Is(err, bmc.ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Fatalf("error leaks password: %v", err)
	}
}

func TestUnreachable(t *testing.T) {
	cfg := Config{Endpoint: "https://127.0.0.1:1", Username: "u", Password: "p",
		PinSHA256: goodPin, Timeout: time.Second}
	d, _ := New(cfg)
	_, err := d.Probe(testCtx(t))
	if !errors.Is(err, bmc.ErrUnreachable) {
		t.Fatalf("want ErrUnreachable, got %v", err)
	}
}

func TestServerErrorStatus(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithStatus("/redfish/v1/Systems/System.Embedded.1", 500))
	d := driverFor(t, s)
	_, err := d.Probe(testCtx(t))
	if !errors.Is(err, bmc.ErrBMC) {
		t.Fatalf("want ErrBMC, got %v", err)
	}
}

func TestUnsafeURIsAreRejected(t *testing.T) {
	s := mockFor(t, idrac9)
	d := driverFor(t, s)
	for _, u := range []string{
		"https://evil.example/redfish/v1", "/redfish/v1/../../x", "/other", "//evil/redfish/v1",
		"/redfish/v1/%2e%2e/x", "/redfish/v1/x?y", "/redfish/v1/x#y", "/redfish/v1/a b", "/redfish/v1/\x00", "/redfish/v1/" + strings.Repeat("a", 600),
	} {
		var v map[string]any
		if err := d.GetJSON(testCtx(t), u, &v); !errors.Is(err, bmc.ErrInvalidConfig) {
			t.Errorf("GetJSON(%q) = %v, want ErrInvalidConfig", u, err)
		}
	}
	if len(s.Requests()) != 0 {
		t.Fatalf("unsafe URI reached server: %+v", s.Requests())
	}
}

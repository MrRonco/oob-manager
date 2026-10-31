package secprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"oob-manager/internal/bmc"
)

// recorder is an HTTP handler that answers by method and records what it saw.
type recorder struct {
	mu      sync.Mutex
	methods []string
	paths   []string
	auth    int
	answer  func(w http.ResponseWriter, r *http.Request)
}

func (rc *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rc.mu.Lock()
	rc.methods = append(rc.methods, r.Method)
	rc.paths = append(rc.paths, r.URL.Path)
	if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		rc.auth++
	}
	rc.mu.Unlock()
	rc.answer(w, r)
}

func (rc *recorder) seen() ([]string, []string, int) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]string(nil), rc.methods...), append([]string(nil), rc.paths...), rc.auth
}

func plainServer(t *testing.T, answer func(w http.ResponseWriter, r *http.Request)) (netip.AddrPort, *recorder) {
	t.Helper()
	rc := &recorder{answer: answer}
	ts := httptest.NewServer(rc)
	t.Cleanup(ts.Close)
	return netip.MustParseAddrPort(strings.TrimPrefix(ts.URL, "http://")), rc
}

func TestCheckHTTPRedirectsToHTTPS(t *testing.T) {
	addr, rc := plainServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://192.0.2.10/", http.StatusMovedPermanently)
	})
	p := CheckHTTP(testCtx(t), addr, Options{})
	if !p.Read.OK() || p.Status != 301 || !p.Redirect || !p.ToHTTPS || p.Port != int(addr.Port()) {
		t.Fatalf("probe %+v", p)
	}
	methods, paths, auth := rc.seen()
	if len(methods) != 1 || methods[0] != http.MethodHead || paths[0] != "/" || auth != 0 {
		t.Fatalf("want one HEAD / without credentials: %v %v %d", methods, paths, auth)
	}
}

func TestCheckHTTPServesPlainPages(t *testing.T) {
	addr, _ := plainServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("login")) })
	if p := CheckHTTP(testCtx(t), addr, Options{}); !p.Read.OK() || p.Status != 200 || p.Redirect {
		t.Fatalf("probe %+v", p)
	}
	addr, _ = plainServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://192.0.2.10/login", http.StatusFound)
	})
	if p := CheckHTTP(testCtx(t), addr, Options{}); !p.Redirect || p.ToHTTPS {
		t.Fatalf("a redirect to plain HTTP is not to HTTPS: %+v", p)
	}
}

func TestCheckHTTPFallsBackToGETWhenHEADIsRefused(t *testing.T) {
	addr, rc := plainServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		http.Redirect(w, r, "https://192.0.2.10/", http.StatusFound)
	})
	p := CheckHTTP(testCtx(t), addr, Options{})
	methods, _, _ := rc.seen()
	if !p.ToHTTPS || len(methods) != 2 || methods[1] != http.MethodGet {
		t.Fatalf("probe %+v methods %v", p, methods)
	}
}

func TestCheckHTTPClosedPort(t *testing.T) {
	p := CheckHTTP(testCtx(t), closedAddr(t), Options{})
	if p.Read.State != bmc.ReadFailed || p.Read.Class != bmc.ClassUnreachable {
		t.Fatalf("closed port %+v", p.Read)
	}
}

func wsmanServer(t *testing.T, answer func(w http.ResponseWriter, r *http.Request)) (netip.AddrPort, []byte, *recorder) {
	t.Helper()
	cert, leaf := makeCert(t, certSpec{key: ecKey(t), subject: pkix.Name{CommonName: "bmc"}})
	rc := &recorder{answer: answer}
	ts := httptest.NewUnstartedServer(rc)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return netip.MustParseAddrPort(strings.TrimPrefix(ts.URL, "https://")), pinOf(leaf), rc
}

func TestCheckWSMan(t *testing.T) {
	addr, pin, rc := wsmanServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wsman" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	p := CheckWSMan(testCtx(t), addr, pin, Options{})
	if !p.Read.OK() || p.Status != 401 || p.ControlStatus != 404 {
		t.Fatalf("probe %+v", p)
	}
	methods, paths, auth := rc.seen()
	if len(methods) != 2 || methods[0] != http.MethodHead || methods[1] != http.MethodHead || paths[0] != "/wsman" ||
		paths[1] != controlPath || auth != 0 {
		t.Fatalf("want two HEADs without credentials: %v %v %d", methods, paths, auth)
	}
}

func TestCheckWSManPinMismatch(t *testing.T) {
	addr, _, rc := wsmanServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	p := CheckWSMan(testCtx(t), addr, make([]byte, 32), Options{})
	if p.Read.State != bmc.ReadFailed || p.Read.Class != bmc.ClassTLS {
		t.Fatalf("pin mismatch %+v", p.Read)
	}
	if methods, _, _ := rc.seen(); len(methods) != 0 {
		t.Fatalf("nothing may be sent to an unpinned host: %v", methods)
	}
}

func TestRoundTripperRefusesOtherMethods(t *testing.T) {
	rt := readOnlyTransport{next: http.DefaultTransport}
	req := httptest.NewRequestWithContext(testCtx(t), http.MethodPost, "http://192.0.2.1/", nil)
	resp, err := rt.RoundTrip(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("POST must be refused before it is sent")
	}
}

// TestCheckHTTPRefusedMeansClosed: only a connection refused marks the port closed; any
// other failure to connect (no route, a dialer refusal) is just unreachable.
func TestCheckHTTPRefusedMeansClosed(t *testing.T) {
	p := CheckHTTP(testCtx(t), closedAddr(t), Options{})
	if p.Read.State != bmc.ReadFailed || p.Read.Class != bmc.ClassUnreachable || !p.Refused {
		t.Fatalf("closed port %+v", p)
	}
	o := Options{Dial: func(context.Context, string, string) (net.Conn, error) { return nil, errDialRefused }}
	if p := CheckHTTP(testCtx(t), closedAddr(t), o); p.Read.State != bmc.ReadFailed || p.Refused {
		t.Fatalf("dialer error %+v", p)
	}
}

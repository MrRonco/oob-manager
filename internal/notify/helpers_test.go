package notify

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/secrets"
)

var update = flag.Bool("update", false, "rewrite golden files")

// fixedNow is the clock of every golden test.
var fixedNow = time.Date(2026, 10, 21, 14, 3, 0, 0, time.UTC)

// captured is one request a receiver saw.
type captured struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   []byte
}

// receiver is a fake push service: it records requests and answers from a script of
// status codes (the last one repeats).
type receiver struct {
	srv   *httptest.Server
	mu    sync.Mutex
	reqs  []captured
	codes []int
	hook  func(w http.ResponseWriter) bool // optional: handle the response itself
}

func newReceiver(t *testing.T, tlsOn bool, codes ...int) *receiver {
	t.Helper()
	if len(codes) == 0 {
		codes = []int{http.StatusOK}
	}
	r := &receiver{codes: codes}
	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.reqs = append(r.reqs, captured{Method: req.Method, Path: req.URL.Path, Query: req.URL.RawQuery,
			Header: req.Header.Clone(), Body: b})
		code := r.codes[min(len(r.reqs)-1, len(r.codes)-1)]
		hook := r.hook
		r.mu.Unlock()
		if hook != nil && hook(w) {
			return
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"status":1,"echo":"receiver text never reaches logs"}`))
	})
	if tlsOn {
		r.srv = httptest.NewTLSServer(h)
	} else {
		r.srv = httptest.NewServer(h)
	}
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) requests() []captured {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]captured(nil), r.reqs...)
}

func (r *receiver) count() int { return len(r.requests()) }

// loopback allows the test receivers (127.0.0.1) through the SSRF policy.
var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}

// transportFor trusts r's certificate and allows loopback.
func transportFor(r *receiver) Transport {
	tr := Transport{Policy: Policy{Allowed: loopback}, Timeout: 3 * time.Second}
	if cert := r.srv.Certificate(); cert != nil {
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		tr.TLS = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return tr
}

func testEvent() Event {
	return Event{ID: "0123456789abcdef0123456789abcdef", Class: ClassHealth, Severity: SeverityCritical,
		ServerID: "srv-a", ServerName: "Storage node", Key: "health/srv-a",
		Title: "Storage node: health Critical", Message: "Storage node reports Critical health (was OK).",
		Detail: []string{"Critical: The power input for power supply 2 is lost."}, At: fixedNow}
}

func sec(token, user, password string) Secrets {
	var s Secrets
	if token != "" {
		s.Token = secrets.New(token)
	}
	if user != "" {
		s.User = secrets.New(user)
	}
	if password != "" {
		s.Password = secrets.New(password)
	}
	return s
}

func allClasses() []Class { return Classes() }

// golden compares got with testdata/golden/name (rewritten with -update).
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) // #nosec G304 -- test fixture path
	if err != nil {
		t.Fatalf("golden %s: %v (run go test -update)", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("golden %s mismatch:\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

// wire renders a captured request for a golden file: method, path, query, the
// headers that are part of the contract (sorted) and the body.
func wire(c captured, headers ...string) []byte {
	var b strings.Builder
	b.WriteString(c.Method + " " + c.Path)
	if c.Query != "" {
		b.WriteString("?" + c.Query)
	}
	b.WriteString("\n")
	sort.Strings(headers)
	for _, h := range headers {
		if v := c.Header.Get(h); v != "" {
			b.WriteString(h + ": " + v + "\n")
		}
	}
	b.WriteString("\n")
	b.Write(c.Body)
	b.WriteString("\n")
	return []byte(b.String())
}

// logBuffer captures a logger's output.
func logBuffer() (*slog.Logger, *syncBuf) {
	var b syncBuf
	return slog.New(slog.NewTextHandler(&b, &slog.HandlerOptions{Level: slog.LevelDebug})), &b
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// waitFor polls cond for up to 5 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// fmtAll renders v with every common verb.
func fmtAll(v any) string {
	return fmt.Sprintf("%v %+v %#v %s %q", v, v, v, v, v)
}

package fwcatalog

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/egress"
	"oob-manager/internal/firmware/catalog"
)

// catalogServer serves /c.xml.gz and /c.xml.gz.sign and records every path asked for.
type catalogServer struct {
	*httptest.Server
	mu    sync.Mutex
	paths []string
	h     func(w http.ResponseWriter, r *http.Request) bool // true: handled
}

func newCatalogServer(t *testing.T, data, sig []byte) *catalogServer {
	t.Helper()
	s := &catalogServer{}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.paths = append(s.paths, r.URL.Path)
		h := s.h
		s.mu.Unlock()
		if h != nil && h(w, r) {
			return
		}
		switch r.URL.Path {
		case "/c.xml.gz":
			if r.Header.Get("If-None-Match") == `"v1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"v1"`)
			w.Header().Set("Last-Modified", "Thu, 22 Oct 2026 13:00:59 GMT")
			_, _ = w.Write(data)
		case "/c.xml.gz.sign":
			_, _ = w.Write(sig)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *catalogServer) fetcher() Fetcher {
	f := Fetcher{URL: s.URL + "/c.xml.gz", UserAgent: "oob-manager/test",
		Policy: egress.Policy{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}
	if tr, ok := s.Client().Transport.(*http.Transport); ok {
		f.TLS = tr.TLSClientConfig
	}
	return f
}

func (s *catalogServer) asked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.paths...)
}

func TestFetchAndConditionalGet(t *testing.T) {
	s := newCatalogServer(t, []byte("catalog-bytes"), []byte("sig"))
	dir := t.TempDir()
	got, err := s.fetcher().Fetch(context.Background(), dir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(got.File)
	if string(body) != "catalog-bytes" || string(got.Sig) != "sig" || got.ETag != `"v1"` || got.LastModified == "" {
		t.Fatalf("fetched %+v %q", got, body)
	}
	again, err := s.fetcher().Fetch(context.Background(), dir, got.ETag, got.LastModified)
	if err != nil || !again.NotModified || again.File != "" {
		t.Fatalf("conditional: %+v %v", again, err)
	}
	// Only the catalog and its signature are ever requested: never a package path.
	for _, p := range s.asked() {
		if p != "/c.xml.gz" && p != "/c.xml.gz.sign" {
			t.Fatalf("asked for %s", p)
		}
	}
}

func TestFetchFailures(t *testing.T) {
	big := strings.Repeat("x", 100)
	cases := []struct {
		name  string
		h     func(w http.ResponseWriter, r *http.Request) bool
		class error
		text  string
	}{
		{"redirect", func(w http.ResponseWriter, r *http.Request) bool {
			http.Redirect(w, r, "https://elsewhere.example.net/c.xml.gz", http.StatusFound)
			return true
		}, catalog.ErrDownload, "redirect"},
		{"server error", func(w http.ResponseWriter, _ *http.Request) bool {
			w.WriteHeader(http.StatusBadGateway)
			return true
		}, catalog.ErrDownload, "502"},
		{"announced too large", func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path != "/c.xml.gz" {
				return false
			}
			w.Header().Set("Content-Length", "99999999")
			w.WriteHeader(http.StatusOK)
			return true
		}, catalog.ErrSize, ""},
		{"no signature", func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path != "/c.xml.gz.sign" {
				return false
			}
			http.NotFound(w, r)
			return true
		}, catalog.ErrSignature, "404"},
		{"signature too large", func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path != "/c.xml.gz.sign" {
				return false
			}
			_, _ = w.Write([]byte(strings.Repeat(big, 50)))
			return true
		}, catalog.ErrSignature, "larger"},
	}
	for _, c := range cases {
		s := newCatalogServer(t, []byte("data"), []byte("sig"))
		s.h = c.h
		dir := t.TempDir()
		_, err := s.fetcher().Fetch(context.Background(), dir, "", "")
		if !errors.Is(err, c.class) || !strings.Contains(err.Error(), c.text) {
			t.Errorf("%s: %v", c.name, err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("%s: left %d files", c.name, len(entries))
		}
	}
}

func TestFetchStreamingCapAndStall(t *testing.T) {
	s := newCatalogServer(t, nil, []byte("sig"))
	s.h = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/c.xml.gz" {
			return false
		}
		chunk := make([]byte, 1<<20)
		for range MaxCatalogBytes>>20 + 2 { // chunked, no Content-Length
			if _, err := w.Write(chunk); err != nil {
				return true
			}
		}
		return true
	}
	if _, err := s.fetcher().Fetch(context.Background(), t.TempDir(), "", ""); !errors.Is(err, catalog.ErrSize) {
		t.Fatalf("chunked oversize: %v", err)
	}
	s.h = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/c.xml.gz" {
			return false
		}
		_, _ = w.Write([]byte("start"))
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		time.Sleep(500 * time.Millisecond)
		return true
	}
	f := s.fetcher()
	f.Idle = 50 * time.Millisecond
	_, err := f.Fetch(context.Background(), t.TempDir(), "", "")
	if !errors.Is(err, catalog.ErrDownload) || !strings.Contains(err.Error(), "stalled") {
		t.Fatalf("stall: %v", err)
	}
}

func TestFetchRefusesPlainHTTP(t *testing.T) {
	for _, u := range []string{"http://downloads.example.net/c.xml.gz", "https:///c", "::"} {
		if _, err := (Fetcher{URL: u}).Fetch(context.Background(), t.TempDir(), "", ""); !errors.Is(err, catalog.ErrDownload) {
			t.Errorf("%q: %v", u, err)
		}
	}
}

func TestFetchRefusesAPrivateAddressByPolicy(t *testing.T) {
	s := newCatalogServer(t, []byte("data"), []byte("sig"))
	f := s.fetcher()
	f.Policy = egress.Policy{Setting: "firmware.catalog.allowed_networks"}
	_, err := f.Fetch(context.Background(), t.TempDir(), "", "")
	if !errors.Is(err, catalog.ErrDownload) || !errors.Is(err, egress.ErrBlocked) ||
		!strings.Contains(err.Error(), "firmware.catalog.allowed_networks") {
		t.Fatalf("private address: %v", err)
	}
	if len(s.asked()) != 0 {
		t.Fatal("the request reached the server")
	}
	if !strings.Contains(downloadErr(&egress.DNSError{}).Error(), "resolve") ||
		!strings.Contains(downloadErr(context.DeadlineExceeded).Error(), "timed out") ||
		!strings.Contains(downloadErr(errors.New("x")).Error(), "network") {
		t.Error("downloadErr classes")
	}
}

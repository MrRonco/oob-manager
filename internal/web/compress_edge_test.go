package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Review R4: the edges of Compress (q-values, HEAD, 304, an existing encoding or Vary, an
// explicit status, a flush before any write).

func TestAcceptsGzipParsesQValues(t *testing.T) {
	for _, c := range []struct {
		header string
		want   bool
	}{
		{"gzip", true}, {"GZIP", true}, {"br, gzip", true}, {"gzip;q=1", true}, {"gzip; q=0.5", true}, {"gzip;q=0.001", true},
		{"", false}, {"br", false}, {"gzip;q=0", false}, {"gzip; q=0.0", false}, {"gzip;q=0.00", false}, {"gzip;q=0.000", false},
		{"gzip;Q=0", false}, {"gzip ; q = 0", false}, {"identity, gzip;q=0, br", false}, {"gzip;q=abc", false}, {"gzip;q=2", false},
		{"gzip;level=1;q=0", false}, {"x-gzip", false},
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://oob.test/", nil)
		req.Header.Set("Accept-Encoding", c.header)
		if got := acceptsGzip(req); got != c.want {
			t.Errorf("Accept-Encoding %q: accepted %v, want %v", c.header, got, c.want)
		}
	}
}

func serve(t *testing.T, h http.Handler, method, target string, hdr ...string) served {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return served{StatusCode: res.StatusCode, Header: res.Header, Body: b}
}

// served is a response as the client got it: the headers sent with the status line
// (later header changes do not count) and the whole body.
type served struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func encoding(r served) string { return r.Header.Get("Content-Encoding") }

func TestCompressLeavesHeadAndNotModifiedAlone(t *testing.T) {
	if r := serve(t, Compress()(textHandler("text/html", 4000)), http.MethodHead, "https://oob.test/", "Accept-Encoding", "gzip"); encoding(r) != "" {
		t.Fatal("a HEAD response was marked gzip")
	}
	notModified := Compress()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.WriteHeader(http.StatusNotModified)
	}))
	if r := serve(t, notModified, http.MethodGet, "https://oob.test/static/app.css", "Accept-Encoding", "gzip"); r.StatusCode != http.StatusNotModified || encoding(r) != "" {
		t.Fatalf("304: %d %v", r.StatusCode, r.Header)
	}
}

func TestCompressKeepsAnExistingEncodingAndVary(t *testing.T) {
	pre := Compress()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Header().Set("Content-Encoding", "br")
		_, _ = io.WriteString(w, strings.Repeat("b", 4000))
	}))
	r := serve(t, pre, http.MethodGet, "https://oob.test/x.css", "Accept-Encoding", "gzip, br")
	if encoding(r) != "br" {
		t.Fatalf("an encoded body was re-encoded: %v", r.Header)
	}
	if b := r.Body; len(b) != 4000 {
		t.Fatalf("body changed: %d bytes", len(b))
	}
	// A Vary set before or after the middleware is kept, and Accept-Encoding is listed once.
	outer := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Vary", "Origin")
			next.ServeHTTP(w, r)
		})
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Vary", "Cookie")
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, strings.Repeat("a", 4000))
	})
	twice := outer(Compress()(Compress()(inner)))
	r = serve(t, twice, http.MethodGet, "https://oob.test/", "Accept-Encoding", "gzip")
	vary := strings.Join(r.Header.Values("Vary"), ", ")
	if !strings.Contains(vary, "Origin") || !strings.Contains(vary, "Cookie") || strings.Count(vary, "Accept-Encoding") != 1 {
		t.Fatalf("Vary = %q", vary)
	}
}

// (Plain text: an HTML error page is never compressed, TestCompressSkipsErrorPagesAndPostAnswers.)
func TestCompressHonoursAnExplicitStatus(t *testing.T) {
	h := Compress()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		w.WriteHeader(http.StatusInternalServerError) // ignored, as net/http would
		_, _ = io.WriteString(w, strings.Repeat("n", 4000))
	}))
	r := serve(t, h, http.MethodGet, "https://oob.test/missing", "Accept-Encoding", "gzip")
	b := r.Body
	if r.StatusCode != http.StatusNotFound || encoding(r) != "gzip" || gunzip(t, b) != strings.Repeat("n", 4000) {
		t.Fatalf("explicit status: %d %v", r.StatusCode, r.Header)
	}
}

// A flush before any write decides first: the headers that go out say gzip, and the body
// that follows is gzip.
func TestCompressFlushBeforeWriteDecidesFirst(t *testing.T) {
	h := Compress()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = io.WriteString(w, strings.Repeat("line\n", 200))
	}))
	r := serve(t, h, http.MethodGet, "https://oob.test/stream", "Accept-Encoding", "gzip")
	b := r.Body
	if encoding(r) != "gzip" || r.Header.Get("Content-Length") != "" || gunzip(t, b) != strings.Repeat("line\n", 200) {
		t.Fatalf("flush first: %v (%d bytes)", r.Header, len(b))
	}
}

package web

import (
	"bufio"
	"compress/gzip"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Audit A9/R2-28: nothing was compressed. Compress gzips text responses (HTML, CSS,
// JavaScript, SVG, JSON, plain text) for clients that accept it, with Vary set, and
// leaves binary bodies, tiny bodies, ranges and WebSocket upgrades alone.

func textHandler(ctype string, size int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ctype)
		body := strings.Repeat("a", size)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = io.WriteString(w, body)
	})
}

func get(t *testing.T, h http.Handler, hdr ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://oob.test/page", nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func gunzip(t *testing.T, b []byte) string {
	t.Helper()
	r, err := gzip.NewReader(strings.NewReader(string(b)))
	if err != nil {
		t.Fatalf("not gzip: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestCompressGzipsTextWhenAccepted(t *testing.T) {
	h := Compress()(textHandler("text/html; charset=utf-8", 4000))
	rec := get(t, h, "Accept-Encoding", "gzip, br")
	if rec.Header().Get("Content-Encoding") != "gzip" || rec.Header().Get("Vary") != "Accept-Encoding" ||
		rec.Header().Get("Content-Length") != "" {
		t.Fatalf("headers %v", rec.Header())
	}
	if got := gunzip(t, rec.Body.Bytes()); got != strings.Repeat("a", 4000) {
		t.Fatalf("body round trip failed (%d bytes)", len(got))
	}
	if rec.Body.Len() >= 4000 {
		t.Fatalf("compressed body is %d bytes", rec.Body.Len())
	}
	// Without Accept-Encoding the body is sent as is, and Vary still says so.
	rec = get(t, h)
	if rec.Header().Get("Content-Encoding") != "" || rec.Header().Get("Vary") != "Accept-Encoding" || rec.Body.Len() != 4000 {
		t.Fatalf("identity: %v %d", rec.Header(), rec.Body.Len())
	}
}

func TestCompressCoversTheTextTypesOnly(t *testing.T) {
	for _, c := range []struct {
		ctype string
		want  bool
	}{
		{"text/html; charset=utf-8", true}, {"text/css", true}, {"application/javascript", true}, {"text/javascript; charset=utf-8", true},
		{"image/svg+xml", true}, {"application/json", true}, {"application/problem+json", true}, {"text/plain; version=0.0.4", true},
		{"image/png", false}, {"application/octet-stream", false}, {"font/woff2", false},
	} {
		rec := get(t, Compress()(textHandler(c.ctype, 4000)), "Accept-Encoding", "gzip")
		if got := rec.Header().Get("Content-Encoding") == "gzip"; got != c.want {
			t.Errorf("%s: compressed %v, want %v", c.ctype, got, c.want)
		}
	}
}

func TestCompressLeavesSmallBodiesRangesAndUpgradesAlone(t *testing.T) {
	small := get(t, Compress()(textHandler("text/html", 200)), "Accept-Encoding", "gzip")
	if small.Header().Get("Content-Encoding") != "" || small.Body.Len() != 200 {
		t.Fatalf("a 200-byte body was compressed: %v", small.Header())
	}
	rng := get(t, Compress()(textHandler("text/html", 4000)), "Accept-Encoding", "gzip", "Range", "bytes=0-99")
	if rng.Header().Get("Content-Encoding") != "" {
		t.Fatal("a range request was compressed")
	}
	// A WebSocket upgrade must reach the handler with the raw ResponseWriter (hijacking).
	var sawHijacker bool
	ws := Compress()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, sawHijacker = w.(http.Hijacker)
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://oob.test/servers/x/console/ws", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	rec := httptest.NewRecorder()
	ws.ServeHTTP(hijackable{rec}, req)
	if !sawHijacker || rec.Header().Get("Content-Encoding") != "" {
		t.Fatal("an upgrade request was wrapped")
	}
}

// hijackable is a recorder that also implements http.Hijacker, like a real connection.
type hijackable struct{ *httptest.ResponseRecorder }

func (hijackable) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, http.ErrNotSupported
}

func TestCompressStreamsAndFlushes(t *testing.T) {
	h := Compress()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		for range 100 {
			_, _ = io.WriteString(w, strings.Repeat("line of log text\n", 4))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}))
	rec := get(t, h, "Accept-Encoding", "gzip")
	if rec.Header().Get("Content-Encoding") != "gzip" || !rec.Flushed {
		t.Fatalf("streamed response: %v flushed=%v", rec.Header(), rec.Flushed)
	}
	if got := gunzip(t, rec.Body.Bytes()); len(got) != 100*4*len("line of log text\n") {
		t.Fatalf("round trip %d bytes", len(got))
	}
}

// NewHandler puts Compress in the standard chain: a page is gzipped when asked for.
func TestChainCompressesPages(t *testing.T) {
	h, err := NewHandler(textHandler("text/html; charset=utf-8", 4000), Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	rec := get(t, h, "Accept-Encoding", "gzip")
	if rec.Header().Get("Content-Encoding") != "gzip" || rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("chain: %v", rec.Header())
	}
}

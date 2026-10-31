package web

import (
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Compression (audit A9/R2-28): pages, stylesheets, scripts, SVG, JSON and plain text
// are gzipped for clients that accept it, with Vary: Accept-Encoding so caches keep the
// variants apart. Left alone: other content types, bodies under compressMinBytes with a
// known length, Range requests (a partial body must stay byte-addressable), HEAD, and
// connection upgrades (the console WebSockets hijack the raw connection), and HTML other
// than a successful answer to a GET without a query string: a query, an error page that
// echoes the path (404 for an unknown URL) or a POST answer can put attacker-chosen or
// one-time text next to a CSRF token, the setting of a BREACH attack (docs/security.md).
// stdlib only.

// compressMinBytes is the smallest declared body worth compressing.
const compressMinBytes = 512

// compressibleTypes are the media types (without parameters) that are compressed.
var compressibleTypes = map[string]bool{
	"text/html": true, "text/css": true, "text/plain": true, "text/javascript": true, "application/javascript": true,
	"application/json": true, "application/problem+json": true, "image/svg+xml": true,
}

// Compress returns the gzip middleware. Each middleware keeps its own writer pool.
func Compress() Middleware {
	pool := &sync.Pool{New: func() any { return gzip.NewWriter(io.Discard) }}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			addVary(w.Header(), "Accept-Encoding")
			if !acceptsGzip(r) || r.Header.Get("Upgrade") != "" || r.Header.Get("Range") != "" || r.Method == http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}
			gw := &gzipWriter{ResponseWriter: w, pool: pool, plainHTML: r.Method == http.MethodGet && r.URL.RawQuery == ""}
			defer gw.close()
			next.ServeHTTP(gw, r)
		})
	}
}

// acceptsGzip reports whether the client accepts gzip: the coding is listed (any case)
// with no q-value or a q-value above zero. A malformed q-value (RFC 9110 §12.4.2: 0 to
// 1, at most three decimals) counts as not accepted.
func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		name, params, _ := strings.Cut(part, ";")
		if !strings.EqualFold(strings.TrimSpace(name), "gzip") {
			continue
		}
		q, ok := qValue(params)
		return ok && q > 0
	}
	return false
}

// qValue parses the q parameter of one Accept-Encoding element (1 when absent).
func qValue(params string) (float64, bool) {
	for _, p := range strings.Split(params, ";") {
		k, v, _ := strings.Cut(p, "=")
		if !strings.EqualFold(strings.TrimSpace(k), "q") {
			continue
		}
		v = strings.TrimSpace(v)
		q, err := strconv.ParseFloat(v, 64)
		if err != nil || q < 0 || q > 1 || len(v) > len("0.000") {
			return 0, false
		}
		return q, true
	}
	return 1, true
}

// addVary lists token in Vary unless a Vary value already names it.
func addVary(h http.Header, token string) {
	for _, v := range h.Values("Vary") {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return
			}
		}
	}
	h.Add("Vary", token)
}

// gzipWriter decides on the first WriteHeader or Write whether the response is worth
// compressing (type, declared size, status), then either gzips or passes through.
type gzipWriter struct {
	http.ResponseWriter
	pool    *sync.Pool
	gz      *gzip.Writer
	decided bool
	pass    bool
	// plainHTML: a GET without a query string, the only request whose HTML may be
	// compressed, and then only on success (BREACH).
	plainHTML bool
}

func (g *gzipWriter) decide(status int) {
	g.decided = true
	h := g.Header()
	ctype, _, _ := strings.Cut(h.Get("Content-Type"), ";")
	small := false
	if cl := h.Get("Content-Length"); cl != "" {
		n, err := strconv.Atoi(cl)
		small = err == nil && n < compressMinBytes
	}
	noBody := status == http.StatusNoContent || status == http.StatusNotModified || status == http.StatusSwitchingProtocols
	ctype = strings.TrimSpace(strings.ToLower(ctype))
	if !compressibleTypes[ctype] || small || noBody || h.Get("Content-Encoding") != "" || (ctype == "text/html" && (!g.plainHTML || status >= http.StatusBadRequest)) {
		g.pass = true
		g.ResponseWriter.WriteHeader(status)
		return
	}
	h.Del("Content-Length")
	h.Set("Content-Encoding", "gzip")
	gz, _ := g.pool.Get().(*gzip.Writer)
	gz.Reset(g.ResponseWriter)
	g.gz = gz
	g.ResponseWriter.WriteHeader(status)
}

// WriteHeader decides once; a repeated call is ignored (net/http would only warn).
func (g *gzipWriter) WriteHeader(status int) {
	if !g.decided {
		g.decide(status)
	}
}

func (g *gzipWriter) Write(p []byte) (int, error) {
	if !g.decided {
		if g.Header().Get("Content-Type") == "" {
			g.Header().Set("Content-Type", http.DetectContentType(p))
		}
		g.decide(http.StatusOK)
	}
	if g.pass {
		return g.ResponseWriter.Write(p)
	}
	return g.gz.Write(p)
}

// Flush forwards a flush (streamed responses), compressing what was written so far. A
// flush before any write decides first, so the headers it sends match the body after.
func (g *gzipWriter) Flush() {
	if !g.decided {
		g.decide(http.StatusOK)
	}
	if g.gz != nil {
		_ = g.gz.Flush()
	}
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (g *gzipWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

// close finishes the gzip stream and returns the writer to the pool.
func (g *gzipWriter) close() {
	if g.gz == nil {
		return
	}
	_ = g.gz.Close()
	g.gz.Reset(io.Discard)
	g.pool.Put(g.gz)
	g.gz = nil
}

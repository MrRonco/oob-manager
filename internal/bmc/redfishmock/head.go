package redfishmock

import (
	"bytes"
	"io"
	"net/http"
	"strings"
)

// WSManPath is where Dell iDRACs serve WS-Management (remote RACADM, OpenManage).
const WSManPath = "/wsman"

// WithWSMan makes the mock answer /wsman like a WS-Management service that wants
// credentials (401); without it, /wsman is 404 like any path outside Redfish.
func WithWSMan() Option {
	return func(c *config) { c.wsman = true }
}

// Heads counts HEAD requests. HEAD is a read: it is served like GET without a body and
// never counted by OtherWrites.
func (s *Server) Heads() int {
	n := 0
	for _, r := range s.Requests() {
		if r.Method == http.MethodHead {
			n++
		}
	}
	return n
}

// serveOutside answers GET and HEAD of paths outside /redfish/v1 (the security checks'
// WS-Management probe and its control path). Other methods fall through to the write
// handler, which refuses and counts them.
func (s *Server) serveOutside(w http.ResponseWriter, r *http.Request, path string) bool {
	if path == servicePrefix || strings.HasPrefix(path, servicePrefix+"/") {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if s.cfg.wsman && path == WSManPath {
		w.Header().Set("WWW-Authenticate", `Basic realm="wsman"`)
		w.WriteHeader(http.StatusUnauthorized)
		return true
	}
	w.WriteHeader(http.StatusNotFound)
	return true
}

// serveHead answers HEAD under /redfish/v1 with the status a GET would get.
func (s *Server) serveHead(w http.ResponseWriter, r *http.Request, path string) {
	if path != servicePrefix && !s.authorised(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	code, _ := s.lookup(path)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
}

// quietHandshakes drops the server's "TLS handshake error" log lines: the security
// checks' probes fail handshakes on purpose (TLS 1.0 and 1.1, suites without forward
// secrecy). Everything else, a handler panic for example, still reaches w.
type quietHandshakes struct{ w io.Writer }

func (q quietHandshakes) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("TLS handshake error")) {
		return len(p), nil
	}
	return q.w.Write(p)
}

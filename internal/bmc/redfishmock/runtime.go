package redfishmock

import (
	"net/http"
	"sync"
)

// runtimeState holds changes made while the mock runs (state-change tests): unlike the
// With* options they can be set and cleared at any time.
type runtimeState struct {
	mu      sync.Mutex
	overlay map[string]string
	down    bool
}

// SetOverlay serves body for path from now on (overrides fixtures and WithOverlay).
func (s *Server) SetOverlay(path, body string) {
	s.rt.mu.Lock()
	defer s.rt.mu.Unlock()
	if s.rt.overlay == nil {
		s.rt.overlay = map[string]string{}
	}
	s.rt.overlay[path] = body
}

// ClearOverlay stops serving a SetOverlay body for path.
func (s *Server) ClearOverlay(path string) {
	s.rt.mu.Lock()
	defer s.rt.mu.Unlock()
	delete(s.rt.overlay, path)
}

// SetDown makes every request (the service root included) answer 503 while down is
// true: the BMC looks unreachable to a poller.
func (s *Server) SetDown(down bool) {
	s.rt.mu.Lock()
	defer s.rt.mu.Unlock()
	s.rt.down = down
}

// Fixture returns the raw fixture document for path (for building overlays from it).
func (s *Server) Fixture(path string) ([]byte, bool) {
	name := pathToFile(path)
	if name == "" {
		return nil, false
	}
	b, err := readFixture(s.dir, name)
	return b, err == nil
}

// runtimeAnswer reports a runtime override for path: (code, body, true) when one applies.
func (s *Server) runtimeAnswer(path string) (int, []byte, bool) {
	s.rt.mu.Lock()
	defer s.rt.mu.Unlock()
	if s.rt.down {
		return http.StatusServiceUnavailable, []byte(`{}`), true
	}
	if body, ok := s.rt.overlay[path]; ok {
		return http.StatusOK, []byte(body), true
	}
	return 0, nil, false
}

// serveRuntime answers from the runtime state when it applies: "down" refuses every
// request; an overlay answers authorised GETs.
func (s *Server) serveRuntime(w http.ResponseWriter, r *http.Request, path string) bool {
	code, body, ok := s.runtimeAnswer(path)
	switch {
	case !ok:
		return false
	case code != http.StatusOK:
		writeJSON(w, code, body)
		return true
	case r.Method != http.MethodGet:
		return false
	case !s.authorised(r):
		writeJSON(w, http.StatusUnauthorized, []byte(`{}`))
		return true
	default:
		writeJSON(w, code, body)
		return true
	}
}

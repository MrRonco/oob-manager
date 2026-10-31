package rfbtest

import "slices"

func (s *Server) update(fn func(*record)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.rec)
}

// Stats is a snapshot of what the server saw.
type Stats struct {
	Connections  int // TCP (or TLS) connections accepted, including banner probes
	AuthOK       int
	AuthFailures int
	Active       int // sessions past ServerInit right now
	Updates      int // framebuffer updates sent
	Pointers     int
}

// Stats returns the counters.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rec
	return Stats{Connections: r.connections, AuthOK: r.authOK, AuthFailures: r.authFailures,
		Active: r.active, Updates: r.updates, Pointers: r.pointers}
}

// MessageTypes returns every client message type received, in order.
func (s *Server) MessageTypes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.rec.types)
}

// Encodings returns every SetEncodings list received.
func (s *Server) Encodings() [][]int32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]int32, len(s.rec.encodings))
	for i, e := range s.rec.encodings {
		out[i] = slices.Clone(e)
	}
	return out
}

// Keys returns every KeyEvent received.
func (s *Server) Keys() []KeyEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.rec.keys)
}

// CutTexts returns every clipboard text received.
func (s *Server) CutTexts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.rec.cutTexts)
}

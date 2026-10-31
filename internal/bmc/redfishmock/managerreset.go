package redfishmock

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"time"
)

// BMC restart (Manager.Reset), served with WithManagerReset. Both captured fixtures
// (iDRAC8 and iDRAC9) use this manager path and advertise GracefulRestart only.
const (
	ManagerPath       = "/redfish/v1/Managers/iDRAC.Embedded.1"
	ManagerResetPath  = ManagerPath + "/Actions/Manager.Reset"
	managerResetBody  = `{"ResetType":"GracefulRestart"}`
	lastResetTimeKey  = "LastResetTime"
	managerDownStatus = http.StatusServiceUnavailable
)

// WithManagerReset serves Manager.Reset for operator sessions. An accepted reset answers
// 204, invalidates every session (as a rebooting BMC does) and makes every request answer
// 503 for downtime; afterwards the manager reports the reset as its LastResetTime when
// the fixture has that property (iDRAC9; iDRAC8 reports none).
func WithManagerReset(downtime time.Duration) Option {
	return func(c *config) {
		c.managerReset = true
		c.downtime = downtime
	}
}

// ManagerResetStats counts Manager.Reset requests. They are not OtherWrites.
type ManagerResetStats struct {
	Resets   int      // accepted resets
	Bodies   []string // raw body of each accepted reset
	Refused  int      // a body other than the canonical one (400)
	Rejected int      // requests without a session (401) or from a non-operator one (403)
	Failed   int      // answered with FailNextManagerReset's status
}

type managerResetSim struct {
	stats     ManagerResetStats
	failNext  int
	downUntil time.Time
	lastReset time.Time
}

// ManagerResetStats returns a copy of the counters.
func (s *Server) ManagerResetStats() ManagerResetStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.mgr.stats
	out.Bodies = slices.Clone(s.mgr.stats.Bodies)
	return out
}

// FailNextManagerReset makes the next operator reset answer code without restarting.
func (s *Server) FailNextManagerReset(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mgr.failNext = code
}

// ManagerRestarting reports whether the simulated BMC is still down after a reset.
func (s *Server) ManagerRestarting() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Now().Before(s.mgr.downUntil)
}

// serveManagerDown answers 503 while the simulated BMC restarts.
func (s *Server) serveManagerDown(w http.ResponseWriter) bool {
	if !s.cfg.managerReset || !s.ManagerRestarting() {
		return false
	}
	writeJSON(w, managerDownStatus, []byte(`{}`))
	return true
}

func (s *Server) managerReset(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	tok := r.Header.Get("X-Auth-Token")
	_, live := s.sess.live[tok]
	if !live || s.sess.users[tok] != OperatorUser {
		s.mgr.stats.Rejected++
		s.mu.Unlock()
		code := http.StatusForbidden // a valid login without the privilege
		if !live {
			code = http.StatusUnauthorized
		}
		writeJSON(w, code, []byte(`{}`))
		return
	}
	s.mu.Unlock()
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	s.mu.Lock()
	defer s.mu.Unlock()
	m := &s.mgr
	switch {
	case err != nil || string(body) != managerResetBody:
		m.stats.Refused++
		writeJSON(w, http.StatusBadRequest, []byte(`{}`))
	case m.failNext != 0:
		code := m.failNext
		m.failNext = 0
		m.stats.Failed++
		writeJSON(w, code, []byte(`{}`))
	default:
		m.stats.Resets++
		m.stats.Bodies = append(m.stats.Bodies, string(body))
		now := time.Now()
		m.downUntil, m.lastReset = now.Add(s.cfg.downtime), now
		s.sess.live, s.sess.users = map[string]string{}, map[string]string{}
		w.WriteHeader(http.StatusNoContent)
	}
}

// patchManager reports the last simulated reset as the manager's LastResetTime, only
// when the fixture has that property.
func (s *Server) patchManager(path string, body []byte) []byte {
	if !s.cfg.managerReset || path != ManagerPath {
		return body
	}
	s.mu.Lock()
	at := s.mgr.lastReset
	s.mu.Unlock()
	if at.IsZero() {
		return body
	}
	var doc map[string]any
	if json.Unmarshal(body, &doc) != nil {
		return body
	}
	if _, ok := doc[lastResetTimeKey]; !ok {
		return body
	}
	doc[lastResetTimeKey] = at.UTC().Format(time.RFC3339)
	out, err := json.Marshal(doc)
	if err != nil {
		return body
	}
	return out
}

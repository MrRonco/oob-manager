package redfishmock

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Power control (ComputerSystem.Reset), served with WithPowerControl. Both captured
// fixtures (iDRAC8 and iDRAC9) use this system path.
const (
	SystemPath      = "/redfish/v1/Systems/System.Embedded.1"
	ResetActionPath = SystemPath + "/Actions/ComputerSystem.Reset"
)

// resetTypes are the ResetType values the mock simulates. Others (Nmi, PushPowerButton)
// are refused even when the fixture advertises them.
var simulated = []string{"On", "GracefulShutdown", "GracefulRestart", "ForceOff", "PowerCycle", "ForceRestart"}

// WithPowerControl serves ComputerSystem.Reset for operator sessions. A reset changes
// the system's PowerState after transition: off-type resets report PoweringOff, On
// reports PoweringOn, and restarts report Off until the transition ends, then On.
func WithPowerControl(transition time.Duration) Option {
	return func(c *config) {
		c.power = true
		c.transition = transition
	}
}

// PowerStats counts reset requests.
type PowerStats struct {
	Resets   []string // ResetType of each accepted request, in order
	Refused  int      // bad body, type not offered, or a reset that makes no sense in this state (400/409)
	Rejected int      // requests without an operator session (403)
	Bodies   []string // raw body of each accepted request
}

type powerSim struct {
	state    string // settled state: On or Off
	from, to string // during a transition: what GET reports, then the settled state
	until    time.Time
	sticky   bool // accept resets but never change state
	failNext int  // answer the next reset with this status
	stats    PowerStats
}

// PowerStats returns a copy of the counters.
func (s *Server) PowerStats() PowerStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.power.stats
	out.Resets = slices.Clone(s.power.stats.Resets)
	out.Bodies = slices.Clone(s.power.stats.Bodies)
	return out
}

// FailNextReset makes the next accepted-looking reset answer code without changing state.
func (s *Server) FailNextReset(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.power.failNext = code
}

// Stick makes the simulated host ignore resets: the BMC answers 204 but PowerState never
// changes (an operating system that ignores ACPI, for example).
func (s *Server) Stick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.power.sticky = true
}

// powerStateNow is the PowerState a GET reports; it settles a finished transition.
func (s *Server) powerStateNow() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &s.power
	if p.to != "" && !time.Now().Before(p.until) {
		p.state, p.from, p.to = p.to, "", ""
	}
	if p.to != "" {
		return p.from
	}
	return p.state
}

// patchSystem rewrites PowerState in the system document.
func (s *Server) patchSystem(path string, body []byte) []byte {
	if !s.cfg.power || path != SystemPath {
		return body
	}
	var doc map[string]any
	if json.Unmarshal(body, &doc) != nil {
		return body
	}
	doc["PowerState"] = s.powerStateNow()
	out, err := json.Marshal(doc)
	if err != nil {
		return body
	}
	return out
}

func (s *Server) reset(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	user := s.sess.users[r.Header.Get("X-Auth-Token")]
	if user != OperatorUser {
		s.power.stats.Rejected++
		s.mu.Unlock()
		writeJSON(w, http.StatusForbidden, []byte(`{}`))
		return
	}
	s.mu.Unlock()
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	rt, ok := s.parseReset(body, err)
	if !ok {
		s.refuse(w, http.StatusBadRequest)
		return
	}
	state := s.powerStateNow()
	if (rt == "On") == (state == "On") {
		s.refuse(w, http.StatusConflict)
		return
	}
	s.applyReset(w, rt, string(body))
}

// parseReset accepts exactly {"ResetType":"<type>"} with a type the fixture offers.
func (s *Server) parseReset(body []byte, err error) (string, bool) {
	var req struct{ ResetType string }
	if err != nil || json.Unmarshal(body, &req) != nil {
		return "", false
	}
	canonical, _ := json.Marshal(map[string]string{"ResetType": req.ResetType})
	if string(body) != string(canonical) || !slices.Contains(simulated, req.ResetType) ||
		!slices.Contains(s.allowedResets(), req.ResetType) {
		return "", false
	}
	return req.ResetType, true
}

func (s *Server) allowedResets() []string {
	_, b := s.lookup(SystemPath)
	var doc struct {
		Actions struct {
			Reset struct {
				Allowable []string `json:"ResetType@Redfish.AllowableValues"`
			} `json:"#ComputerSystem.Reset"`
		}
	}
	_ = json.Unmarshal(b, &doc)
	return doc.Actions.Reset.Allowable
}

func (s *Server) refuse(w http.ResponseWriter, code int) {
	s.mu.Lock()
	s.power.stats.Refused++
	s.mu.Unlock()
	writeJSON(w, code, []byte(`{}`))
}

func (s *Server) applyReset(w http.ResponseWriter, rt, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &s.power
	if p.failNext != 0 {
		code := p.failNext
		p.failNext = 0
		writeJSON(w, code, []byte(`{}`))
		return
	}
	p.stats.Resets = append(p.stats.Resets, rt)
	p.stats.Bodies = append(p.stats.Bodies, body)
	if !p.sticky {
		p.from, p.to = transitionFor(rt)
		p.until = time.Now().Add(s.cfg.transition)
	}
	w.WriteHeader(http.StatusNoContent)
}

// transitionFor is what GET reports during the transition, and the settled state.
func transitionFor(rt string) (from, to string) {
	switch {
	case rt == "On":
		return "PoweringOn", "On"
	case strings.Contains(rt, "Restart"), rt == "PowerCycle":
		return "Off", "On"
	default:
		return "PoweringOff", "Off"
	}
}

// fixturePowerState is the system's PowerState as captured ("On" when unreadable).
func (s *Server) fixturePowerState() string {
	_, b := s.lookup(SystemPath)
	var doc struct{ PowerState string }
	if json.Unmarshal(b, &doc) != nil || doc.PowerState == "" {
		return "On"
	}
	return doc.PowerState
}

package redfishmock

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// Dell iDRAC9 system attributes holding the fan floor (ThermalSettings.1.*), served with
// WithFanFloor. Values follow the iDRAC9 7.00 spike: MinimumFanSpeed 255 = not set
// (automatic), settable range MFSMinimumLimit..MFSMaximumLimit.
const (
	FanFloorAttrsPath = "/redfish/v1/Managers/System.Embedded.1/Attributes"
	FanFloorAuto      = 255
	fanFloorKey       = "ThermalSettings.1.MinimumFanSpeed"
	fanFloorLow       = 35
	fanFloorHigh      = 100
)

// WithFanFloor serves the Dell system attributes with MinimumFanSpeed (initially 255)
// and accepts PATCHes of that single attribute from operator sessions.
func WithFanFloor() Option {
	return func(c *config) { c.fanFloor = true }
}

// FanFloorStats is the fan floor state and the PATCHes received.
type FanFloorStats struct {
	Current  int   // MinimumFanSpeed now
	Patches  []int // every accepted value, in order
	Rejected int   // refused PATCHes (wrong account, body or range)
}

type fanFloorState = FanFloorStats

// FanFloorStats returns a copy of the fan floor state.
func (s *Server) FanFloorStats() FanFloorStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.fan
	out.Patches = append([]int(nil), s.fan.Patches...)
	return out
}

// SetFanFloor changes MinimumFanSpeed as if someone else had (the iDRAC UI, a reset).
func (s *Server) SetFanFloor(v int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fan.Current = v
}

func (s *Server) fanFloorDoc(path string) ([]byte, bool) {
	if !s.cfg.fanFloor || path != FanFloorAttrsPath {
		return nil, false
	}
	s.mu.Lock()
	cur := s.fan.Current
	s.mu.Unlock()
	b, _ := json.Marshal(map[string]any{
		"@odata.id": FanFloorAttrsPath,
		"Id":        "SystemAttributes",
		"Attributes": map[string]any{
			fanFloorKey:                         cur,
			"ThermalSettings.1.MFSMinimumLimit": fanFloorLow,
			"ThermalSettings.1.MFSMaximumLimit": fanFloorHigh,
			"ThermalSettings.1.ThermalProfile":  "Default Thermal Profile Settings",
			"ThermalSettings.1.FanSpeedOffset":  "Off",
		},
	})
	return b, true
}

// patchFanFloor accepts exactly {"Attributes":{"ThermalSettings.1.MinimumFanSpeed":n}}
// with n = 255 or n in [35, 100], from an operator session.
func (s *Server) patchFanFloor(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	user := s.sess.users[r.Header.Get("X-Auth-Token")]
	s.mu.Unlock()
	if user != OperatorUser {
		s.rejectFanFloor(w, http.StatusForbidden)
		return
	}
	v, ok := parseFanFloorPatch(r.Body)
	if !ok {
		s.rejectFanFloor(w, http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.fan.Current = v
	s.fan.Patches = append(s.fan.Patches, v)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, []byte(`{"@Message.ExtendedInfo":[{"MessageId":"Base.1.12.Success"}]}`))
}

func parseFanFloorPatch(body io.Reader) (int, bool) {
	raw, err := io.ReadAll(io.LimitReader(body, 4096))
	if err != nil {
		return 0, false
	}
	var req struct {
		Attributes map[string]int `json:"Attributes"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || len(req.Attributes) != 1 {
		return 0, false
	}
	v, ok := req.Attributes[fanFloorKey]
	if !ok || (v != FanFloorAuto && (v < fanFloorLow || v > fanFloorHigh)) {
		return 0, false
	}
	return v, true
}

func (s *Server) rejectFanFloor(w http.ResponseWriter, code int) {
	s.mu.Lock()
	s.fan.Rejected++
	s.mu.Unlock()
	writeJSON(w, code, []byte(`{}`))
}

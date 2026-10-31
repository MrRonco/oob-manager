package redfishmock

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
)

// Dell iDRAC9 KVM launch (DelliDRACCardService.GetKVMSession), served with WithKVMSession.
const (
	KVMServicePath = "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DelliDRACCardService"
	KVMActionPath  = KVMServicePath + "/Actions/DelliDRACCardService.GetKVMSession"
)

// WithKVMSession serves the Dell card service with the GetKVMSession action and answers
// POSTs to it (operator sessions only) with a fresh temporary user and password.
func WithKVMSession() Option {
	return func(c *config) { c.kvm = true }
}

// KVMStats counts GetKVMSession calls.
type KVMStats struct {
	Launches int      // successful calls
	Rejected int      // calls without an operator session
	Types    []string // SessionTypeName of each successful call
}

type kvmStats = KVMStats

// KVMStats returns a copy of the counters.
func (s *Server) KVMStats() KVMStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.kvm
	out.Types = append([]string(nil), s.kvm.Types...)
	return out
}

func validLogin(user, password string) bool {
	return (user == User && password == Password) || (user == OperatorUser && password == OperatorPassword)
}

func (s *Server) kvmDoc(path string) ([]byte, bool) {
	if !s.cfg.kvm || path != KVMServicePath {
		return nil, false
	}
	b, _ := json.Marshal(map[string]any{
		"@odata.id": KVMServicePath,
		"Id":        "DelliDRACCardService",
		"Actions": map[string]any{
			"#DelliDRACCardService.GetKVMSession": map[string]string{"target": KVMActionPath},
		},
	})
	return b, true
}

func (s *Server) getKVMSession(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	user := s.sess.users[r.Header.Get("X-Auth-Token")]
	if user != OperatorUser {
		s.kvm.Rejected++
		s.mu.Unlock()
		writeJSON(w, http.StatusForbidden, []byte(`{}`))
		return
	}
	s.mu.Unlock()
	var req struct{ SessionTypeName string }
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil || json.Unmarshal(body, &req) != nil || req.SessionTypeName == "" {
		writeJSON(w, http.StatusBadRequest, []byte(`{}`))
		return
	}
	s.mu.Lock()
	s.kvm.Launches++
	s.kvm.Types = append(s.kvm.Types, req.SessionTypeName)
	n := strconv.Itoa(s.kvm.Launches)
	s.mu.Unlock()
	doc, _ := json.Marshal(map[string]string{"TempUsername": "tmpkvm" + n, "TempPassword": "Tmp-pass-" + n})
	writeJSON(w, http.StatusOK, doc)
}

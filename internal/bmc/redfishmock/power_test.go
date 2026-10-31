package redfishmock

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func opLogin(t *testing.T, s *Server) string {
	t.Helper()
	resp, _ := do(t, s, http.MethodPost, s.SessionsURI(), reqOpts{body: `{"UserName":"` + OperatorUser + `","Password":"` + OperatorPassword + `"}`})
	tok := resp.Header.Get("X-Auth-Token")
	if tok == "" {
		t.Fatal("operator login failed")
	}
	return tok
}

// waitPowerState polls until the system reports want, so a loaded machine (-race, many packages
// at once) cannot fail on a fixed sleep.
func waitPowerState(t *testing.T, s *Server, tok, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := powerStateOf(t, s, tok)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("power state %q, want %q", got, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func powerStateOf(t *testing.T, s *Server, tok string) string {
	t.Helper()
	_, b := do(t, s, http.MethodGet, SystemPath, reqOpts{token: tok})
	var doc struct{ PowerState string }
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.PowerState
}

func TestPowerControlTransitions(t *testing.T) {
	s := New(t, FixtureDir(t, "idrac9-r240"), WithPowerControl(time.Second))
	tok := opLogin(t, s)
	target := SystemPath + "/Actions/ComputerSystem.Reset"
	if got := powerStateOf(t, s, tok); got != "On" {
		t.Fatalf("initial state %q", got)
	}
	if r, _ := do(t, s, http.MethodPost, target, reqOpts{token: tok, body: `{"ResetType":"On"}`}); r.StatusCode != http.StatusConflict {
		t.Fatalf("On while on: %d", r.StatusCode)
	}
	if r, _ := do(t, s, http.MethodPost, target, reqOpts{token: tok, body: `{"ResetType":"ForceOff"}`}); r.StatusCode != http.StatusNoContent {
		t.Fatalf("ForceOff: %d", r.StatusCode)
	}
	if got := powerStateOf(t, s, tok); got != "PoweringOff" {
		t.Fatalf("during transition %q", got)
	}
	waitPowerState(t, s, tok, "Off")
	if r, _ := do(t, s, http.MethodPost, target, reqOpts{token: tok, body: `{"ResetType":"On"}`}); r.StatusCode != http.StatusNoContent {
		t.Fatalf("On: %d", r.StatusCode)
	}
	waitPowerState(t, s, tok, "On")
	st := s.PowerStats()
	if len(st.Resets) != 2 || st.Resets[0] != "ForceOff" || st.Resets[1] != "On" || st.Refused != 1 || s.OtherWrites() != 0 {
		t.Fatalf("stats %+v other writes %d", st, s.OtherWrites())
	}
}

func TestPowerControlRestartGoesThroughOff(t *testing.T) {
	s := New(t, FixtureDir(t, "idrac9-r240"), WithPowerControl(time.Second))
	tok := opLogin(t, s)
	target := SystemPath + "/Actions/ComputerSystem.Reset"
	if r, _ := do(t, s, http.MethodPost, target, reqOpts{token: tok, body: `{"ResetType":"PowerCycle"}`}); r.StatusCode != http.StatusNoContent {
		t.Fatalf("PowerCycle: %d", r.StatusCode)
	}
	if got := powerStateOf(t, s, tok); got != "Off" {
		t.Fatalf("during restart %q", got)
	}
	waitPowerState(t, s, tok, "On")
}

func TestPowerControlRefusals(t *testing.T) {
	s := New(t, FixtureDir(t, "idrac8-r730xd"), WithPowerControl(0))
	target := SystemPath + "/Actions/ComputerSystem.Reset"
	ro, _ := login(t, s, s.SessionsURI())
	if r, _ := do(t, s, http.MethodPost, target, reqOpts{token: ro, body: `{"ResetType":"ForceOff"}`}); r.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only account: %d", r.StatusCode)
	}
	op := opLogin(t, s)
	for _, body := range []string{
		`{"ResetType":"PowerCycle"}`,         // not offered by this iDRAC8
		`{"ResetType":"Nmi"}`,                // offered, but not a reset this mock accepts
		`{"ResetType":"ForceOff","Extra":1}`, // anything beyond ResetType
		`{"ResetType":"ForceOff"} `,          // not exactly the canonical body
		`not json`,
	} {
		if r, _ := do(t, s, http.MethodPost, target, reqOpts{token: op, body: body}); r.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d", body, r.StatusCode)
		}
	}
	if r, _ := do(t, s, http.MethodPost, SystemPath+"/Actions/Other", reqOpts{token: op, body: `{}`}); r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("other action: %d", r.StatusCode)
	}
	st := s.PowerStats()
	if len(st.Resets) != 0 || st.Rejected != 1 || st.Refused != 5 || s.OtherWrites() != 1 {
		t.Fatalf("stats %+v other %d", st, s.OtherWrites())
	}
	plain := New(t, FixtureDir(t, "idrac8-r730xd"))
	tok := opLogin(t, plain)
	if r, _ := do(t, plain, http.MethodPost, target, reqOpts{token: tok, body: `{"ResetType":"ForceOff"}`}); r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("without the option a reset is a forbidden write: %d", r.StatusCode)
	}
}

func TestPowerControlFailNext(t *testing.T) {
	s := New(t, FixtureDir(t, "idrac9-r240"), WithPowerControl(0))
	s.FailNextReset(http.StatusInternalServerError)
	tok := opLogin(t, s)
	target := SystemPath + "/Actions/ComputerSystem.Reset"
	if r, _ := do(t, s, http.MethodPost, target, reqOpts{token: tok, body: `{"ResetType":"ForceOff"}`}); r.StatusCode != http.StatusInternalServerError {
		t.Fatalf("injected failure: %d", r.StatusCode)
	}
	if got := powerStateOf(t, s, tok); got != "On" {
		t.Fatalf("a failed reset changed the state: %q", got)
	}
	s.Stick() // the BMC accepts resets but the host never changes state
	if r, _ := do(t, s, http.MethodPost, target, reqOpts{token: tok, body: `{"ResetType":"GracefulShutdown"}`}); r.StatusCode != http.StatusNoContent {
		t.Fatalf("sticky: %d", r.StatusCode)
	}
	if got := powerStateOf(t, s, tok); got != "On" {
		t.Fatalf("sticky host changed state: %q", got)
	}
}

package redfishmock

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func lastResetOf(t *testing.T, s *Server, tok string) (string, bool) {
	t.Helper()
	_, b := do(t, s, http.MethodGet, ManagerPath, reqOpts{token: tok})
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	v, ok := doc[lastResetTimeKey].(string)
	return v, ok
}

func TestManagerResetRestartsTheBMC(t *testing.T) {
	s := New(t, FixtureDir(t, "idrac9-r240"), WithManagerReset(60*time.Millisecond))
	tok := opLogin(t, s)
	before, ok := lastResetOf(t, s, tok)
	if !ok || before == "" {
		t.Fatal("the iDRAC9 fixture reports LastResetTime")
	}
	r, _ := do(t, s, http.MethodPost, ManagerResetPath, reqOpts{token: tok, body: managerResetBody})
	if r.StatusCode != http.StatusNoContent {
		t.Fatalf("reset: %d", r.StatusCode)
	}
	if s.LiveSessions() != 0 || !s.ManagerRestarting() {
		t.Fatalf("sessions %d restarting %v", s.LiveSessions(), s.ManagerRestarting())
	}
	if r, _ := do(t, s, http.MethodGet, servicePrefix, reqOpts{}); r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("while down: %d", r.StatusCode)
	}
	time.Sleep(80 * time.Millisecond)
	tok = opLogin(t, s)
	after, _ := lastResetOf(t, s, tok)
	if after == before {
		t.Fatalf("LastResetTime unchanged: %s", after)
	}
	st := s.ManagerResetStats()
	if st.Resets != 1 || len(st.Bodies) != 1 || st.Bodies[0] != managerResetBody || s.OtherWrites() != 0 {
		t.Fatalf("stats %+v other writes %d", st, s.OtherWrites())
	}
}

func TestManagerResetWithoutLastResetTime(t *testing.T) {
	s := New(t, FixtureDir(t, "idrac8-r730xd"), WithManagerReset(0))
	tok := opLogin(t, s)
	if r, _ := do(t, s, http.MethodPost, ManagerResetPath, reqOpts{token: tok, body: managerResetBody}); r.StatusCode != http.StatusNoContent {
		t.Fatalf("reset: %d", r.StatusCode)
	}
	tok = opLogin(t, s)
	if _, ok := lastResetOf(t, s, tok); ok {
		t.Fatal("iDRAC8 must not grow a LastResetTime")
	}
}

func TestManagerResetRefusals(t *testing.T) {
	s := New(t, FixtureDir(t, "idrac9-r240"), WithManagerReset(0))
	ro, _ := login(t, s, s.SessionsURI())
	if r, _ := do(t, s, http.MethodPost, ManagerResetPath, reqOpts{token: ro, body: managerResetBody}); r.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only account: %d", r.StatusCode)
	}
	tok := opLogin(t, s)
	for _, body := range []string{`{"ResetType":"ForceRestart"}`, `{"ResetType": "GracefulRestart"}`,
		`{"ResetType":"GracefulRestart","X":1}`, ``} {
		if r, _ := do(t, s, http.MethodPost, ManagerResetPath, reqOpts{token: tok, body: body}); r.StatusCode != http.StatusBadRequest {
			t.Fatalf("body %q: %d", body, r.StatusCode)
		}
	}
	s.FailNextManagerReset(http.StatusConflict)
	if r, _ := do(t, s, http.MethodPost, ManagerResetPath, reqOpts{token: tok, body: managerResetBody}); r.StatusCode != http.StatusConflict {
		t.Fatalf("injected: %d", r.StatusCode)
	}
	st := s.ManagerResetStats()
	if st.Resets != 0 || st.Rejected != 1 || st.Refused != 4 || st.Failed != 1 || s.LiveSessions() != 2 {
		t.Fatalf("stats %+v sessions %d", st, s.LiveSessions())
	}
	// Without the option the action is an ordinary forbidden write.
	plain := New(t, FixtureDir(t, "idrac9-r240"))
	tok = opLogin(t, plain)
	if r, _ := do(t, plain, http.MethodPost, ManagerResetPath, reqOpts{token: tok, body: managerResetBody}); r.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("without the option: %d", r.StatusCode)
	}
	if plain.OtherWrites() != 1 {
		t.Fatalf("other writes %d", plain.OtherWrites())
	}
}

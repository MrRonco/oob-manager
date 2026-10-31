package redfishmock

import (
	"net/http"
	"strings"
	"testing"
)

func TestKVMSessionNeedsOperator(t *testing.T) {
	s := New(t, FixtureDir(t, "idrac9-r240"), WithKVMSession())
	coll := s.SessionsURI()
	if r, b := do(t, s, http.MethodGet, KVMServicePath, reqOpts{basic: true}); r.StatusCode != http.StatusOK ||
		!strings.Contains(string(b), KVMActionPath) {
		t.Fatalf("card service: %d %s", r.StatusCode, b)
	}
	roTok, _ := login(t, s, coll)
	if r, _ := do(t, s, http.MethodPost, KVMActionPath, reqOpts{token: roTok, body: `{"SessionTypeName":"x"}`}); r.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only session: %d", r.StatusCode)
	}
	resp, _ := do(t, s, http.MethodPost, coll, reqOpts{body: `{"UserName":"` + OperatorUser + `","Password":"` + OperatorPassword + `"}`})
	opTok := resp.Header.Get("X-Auth-Token")
	if r, _ := do(t, s, http.MethodPost, KVMActionPath, reqOpts{token: opTok, body: `{}`}); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing SessionTypeName: %d", r.StatusCode)
	}
	r, b := do(t, s, http.MethodPost, KVMActionPath, reqOpts{token: opTok, body: `{"SessionTypeName":"x"}`})
	if r.StatusCode != http.StatusOK || !strings.Contains(string(b), `"TempPassword":"Tmp-pass-1"`) {
		t.Fatalf("launch: %d %s", r.StatusCode, b)
	}
	if st := s.KVMStats(); st.Launches != 1 || st.Rejected != 1 || st.Types[0] != "x" || s.OtherWrites() != 0 {
		t.Errorf("stats %+v other %d", st, s.OtherWrites())
	}
	plain := New(t, FixtureDir(t, "idrac9-r240"))
	if r, _ := do(t, plain, http.MethodGet, KVMServicePath, reqOpts{basic: true}); r.StatusCode != http.StatusNotFound {
		t.Errorf("without the option the card service is absent: %d", r.StatusCode)
	}
}

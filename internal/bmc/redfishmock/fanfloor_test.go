package redfishmock

import (
	"net/http"
	"strings"
	"testing"
)

func TestFanFloorAttributes(t *testing.T) {
	s := New(t, FixtureDir(t, "idrac9-r240"), WithFanFloor())
	coll := s.SessionsURI()
	r, b := do(t, s, http.MethodGet, FanFloorAttrsPath, reqOpts{basic: true})
	if r.StatusCode != http.StatusOK || !strings.Contains(string(b), `"ThermalSettings.1.MinimumFanSpeed":255`) ||
		!strings.Contains(string(b), `"ThermalSettings.1.MFSMinimumLimit":35`) {
		t.Fatalf("attributes: %d %s", r.StatusCode, b)
	}
	roTok, _ := login(t, s, coll)
	if r, _ := do(t, s, http.MethodPatch, FanFloorAttrsPath, reqOpts{token: roTok,
		body: `{"Attributes":{"ThermalSettings.1.MinimumFanSpeed":50}}`}); r.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only PATCH: %d", r.StatusCode)
	}
	resp, _ := do(t, s, http.MethodPost, coll, reqOpts{body: `{"UserName":"` + OperatorUser + `","Password":"` + OperatorPassword + `"}`})
	op := resp.Header.Get("X-Auth-Token")
	bad := []string{`{}`, `{"Attributes":{"ThermalSettings.1.MinimumFanSpeed":20}}`,
		`{"Attributes":{"ThermalSettings.1.MinimumFanSpeed":101}}`,
		`{"Attributes":{"ThermalSettings.1.FanSpeedOffset":"Max"}}`,
		`{"Attributes":{"ThermalSettings.1.MinimumFanSpeed":50,"X":1}}`, `not json`}
	for _, body := range bad {
		if r, _ := do(t, s, http.MethodPatch, FanFloorAttrsPath, reqOpts{token: op, body: body}); r.StatusCode != http.StatusBadRequest {
			t.Errorf("PATCH %s: %d", body, r.StatusCode)
		}
	}
	for _, v := range []string{"50", "255"} {
		if r, _ := do(t, s, http.MethodPatch, FanFloorAttrsPath, reqOpts{token: op,
			body: `{"Attributes":{"ThermalSettings.1.MinimumFanSpeed":` + v + `}}`}); r.StatusCode != http.StatusOK {
			t.Fatalf("PATCH %s: %d", v, r.StatusCode)
		}
	}
	st := s.FanFloorStats()
	if st.Current != 255 || len(st.Patches) != 2 || st.Patches[0] != 50 || st.Rejected != 1+len(bad) || s.OtherWrites() != 0 {
		t.Fatalf("stats %+v other %d", st, s.OtherWrites())
	}
	s.SetFanFloor(60)
	if _, b := do(t, s, http.MethodGet, FanFloorAttrsPath, reqOpts{basic: true}); !strings.Contains(string(b), `MinimumFanSpeed":60`) {
		t.Fatalf("after SetFanFloor: %s", b)
	}
	plain := New(t, FixtureDir(t, "idrac9-r240"))
	if r, _ := do(t, plain, http.MethodGet, FanFloorAttrsPath, reqOpts{basic: true}); r.StatusCode != http.StatusNotFound {
		t.Errorf("without the option the attributes are absent: %d", r.StatusCode)
	}
	if r, _ := do(t, plain, http.MethodPatch, FanFloorAttrsPath, reqOpts{basic: true, body: `{}`}); r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PATCH without the option: %d", r.StatusCode)
	}
}

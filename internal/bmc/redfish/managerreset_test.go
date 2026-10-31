package redfish

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
)

func TestIsManagerResetActionURI(t *testing.T) {
	good := []string{
		"/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Manager.Reset",
		"/redfish/v1/Managers/1/Actions/Manager.Reset",
		"/redfish/v1/Managers/bmc_a-1/Actions/Manager.Reset",
	}
	bad := []string{
		"/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Manager.Reset/",
		"/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Manager.ResetToDefaults",
		"/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Oem/DellManager.ResetToDefaults",
		"/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Oem/DellManager.SetCustomDefaults",
		"/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Oem/EID_674_Manager.ExportSystemConfiguration",
		"/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset",
		"/redfish/v1/Managers/../Actions/Manager.Reset",
		"/redfish/v1/Managers/a..b/Actions/Manager.Reset",
		"/redfish/v1/Managers/a/b/Actions/Manager.Reset",
		"/redfish/v1/Managers//Actions/Manager.Reset",
		"/redfish/v1/Managers/a%2f/Actions/Manager.Reset",
		"/redfish/v1/Managers/1/Actions/Manager.Reset?x=1",
		"/redfish/v1/Managers/1/Actions/Manager.Reset#x",
		"/redfish/v1/Managers/1/Actions/Manager.reset",
		"",
	}
	for _, p := range good {
		if !IsManagerResetActionURI(p) {
			t.Errorf("refused %q", p)
		}
	}
	for _, p := range bad {
		if IsManagerResetActionURI(p) {
			t.Errorf("accepted %q", p)
		}
	}
}

func TestManagerResetterSendsOneGracefulRestart(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithManagerReset(200*time.Millisecond))
	r, err := OpenManagerResetter(testCtx(t), operatorConfig(s))
	if err != nil {
		t.Fatal(err)
	}
	if r.Target() != redfishmock.ManagerResetPath {
		t.Fatalf("target %q", r.Target())
	}
	if err := r.Reset(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	// The BMC dropped every session and answers 503 while it restarts: logging out
	// cannot work and is not an error for this action.
	if err := r.Close(testCtx(t)); err != nil {
		t.Fatalf("close while restarting: %v", err)
	}
	st := s.ManagerResetStats()
	if st.Resets != 1 || !slices.Equal(st.Bodies, []string{`{"ResetType":"GracefulRestart"}`}) {
		t.Fatalf("stats %+v", st)
	}
	if s.OtherWrites() != 0 {
		t.Fatalf("other writes %d", s.OtherWrites())
	}
	posts := 0
	for _, req := range s.Requests() {
		if req.Method == http.MethodPost && req.Path != s.SessionsURI() {
			posts++
		}
	}
	if posts != 1 {
		t.Fatalf("%d action POSTs", posts)
	}
}

func TestManagerResetterLogoutAfterTheBMCIsBack(t *testing.T) {
	s := mockFor(t, idrac8, redfishmock.WithManagerReset(0))
	r, err := OpenManagerResetter(testCtx(t), operatorConfig(s))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Reset(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	// The session is gone (401 on DELETE): not an error either.
	if err := r.Close(testCtx(t)); err != nil {
		t.Fatal(err)
	}
}

func managerDocWith(t *testing.T, s *redfishmock.Server, edit func(actions map[string]any)) string {
	t.Helper()
	raw, ok := s.Fixture(redfishmock.ManagerPath)
	if !ok {
		t.Fatal("no manager fixture")
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	actions, _ := doc["Actions"].(map[string]any)
	edit(actions)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestManagerResetterRefusesWhatIsNotTheOwnGracefulRestart(t *testing.T) {
	cases := map[string]func(map[string]any){
		"foreign target": func(a map[string]any) {
			a["#Manager.Reset"] = map[string]any{"target": "/redfish/v1/Managers/Other/Actions/Manager.Reset",
				"ResetType@Redfish.AllowableValues": []string{"GracefulRestart"}}
		},
		"reset to defaults target": func(a map[string]any) {
			a["#Manager.Reset"] = map[string]any{"target": redfishmock.ManagerPath + "/Actions/Manager.ResetToDefaults",
				"ResetType@Redfish.AllowableValues": []string{"GracefulRestart"}}
		},
		"force restart only": func(a map[string]any) {
			a["#Manager.Reset"] = map[string]any{"target": redfishmock.ManagerResetPath,
				"ResetType@Redfish.AllowableValues": []string{"ForceRestart"}}
		},
		"absent": func(a map[string]any) { delete(a, "#Manager.Reset") },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			s := mockFor(t, idrac9, redfishmock.WithManagerReset(0))
			s.SetOverlay(redfishmock.ManagerPath, managerDocWith(t, s, edit))
			if _, err := OpenManagerResetter(testCtx(t), operatorConfig(s)); !errors.Is(err, bmc.ErrUnsupported) {
				t.Fatalf("err = %v", err)
			}
			if st := s.ManagerResetStats(); st.Resets+st.Refused+st.Rejected != 0 || s.LiveSessions() != 0 {
				t.Fatalf("a refused discovery reached the action or left a session: %+v live %d", st, s.LiveSessions())
			}
		})
	}
}

func TestManagerResetterPrivilegeRefusal(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithManagerReset(0))
	r, err := OpenManagerResetter(testCtx(t), configFor(s)) // the read-only account: 403
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(testCtx(t)) }()
	err = r.Reset(testCtx(t))
	if !errors.Is(err, bmc.ErrPrivilege) || bmc.Classify(err) != bmc.ClassAuth {
		t.Fatalf("err = %v (%s)", err, bmc.Classify(err))
	}
}

func TestManagerResetterDoesNotRetryA401(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithManagerReset(0))
	r, err := OpenManagerResetter(testCtx(t), operatorConfig(s))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(testCtx(t)) }()
	s.ExpireSessions()
	if err := r.Reset(testCtx(t)); !errors.Is(err, bmc.ErrAuth) || errors.Is(err, bmc.ErrPrivilege) {
		t.Fatalf("err = %v", err)
	}
	n := 0
	for _, req := range s.Requests() {
		if req.Path == redfishmock.ManagerResetPath {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d POSTs to the action, want 1", n)
	}
}

func TestManagerResetIsRefusedByEveryOtherDriver(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithManagerReset(0))
	ro := driverFor(t, s)
	power, err := New(operatorConfig(s), WithActionPolicy(IsResetActionURI))
	if err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]*Driver{"poller": ro, "power resetter": power} {
		err := d.PostAction(testCtx(t), redfishmock.ManagerResetPath, managerResetBody{ResetType: ManagerResetType}, nil)
		if !errors.Is(err, bmc.ErrMethodNotAllowed) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	for _, req := range s.Requests() {
		if req.Path == redfishmock.ManagerResetPath {
			t.Fatal("a refused POST reached the BMC")
		}
	}
}

func TestProbeReportsManagerReset(t *testing.T) {
	for _, tc := range []struct {
		fixture   string
		lastReset time.Time
	}{
		{idrac8, time.Time{}},
		{idrac9, time.Date(2024, 8, 27, 5, 18, 54, 0, time.UTC)},
	} {
		s := mockFor(t, tc.fixture)
		caps, err := driverFor(t, s).Probe(testCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		f := caps.Flags()
		if !f.ManagerReset || !f.BMCLastReset.Equal(tc.lastReset) ||
			!slices.Equal(caps.ManagerResetTypes(), []string{"GracefulRestart"}) {
			t.Errorf("%s: reset %v last %v types %v", tc.fixture, f.ManagerReset, f.BMCLastReset, caps.ManagerResetTypes())
		}
		assertNoWrites(t, s)
	}
	s := mockFor(t, idrac9)
	s.SetOverlay(redfishmock.ManagerPath, managerDocWith(t, s, func(a map[string]any) {
		a["#Manager.Reset"] = map[string]any{"target": "/redfish/v1/Managers/Other/Actions/Manager.Reset",
			"ResetType@Redfish.AllowableValues": []string{"GracefulRestart"}}
	}))
	caps, err := driverFor(t, s).Probe(testCtx(t))
	if err != nil || caps.Flags().ManagerReset {
		t.Fatalf("foreign target offered: %v %v", caps.Flags().ManagerReset, err)
	}
}

func TestParseLastReset(t *testing.T) {
	if !parseLastReset("garbage").IsZero() || !parseLastReset("").IsZero() {
		t.Fatal("unreadable LastResetTime must be zero")
	}
	if got := parseLastReset(" 2024-08-27T01:18:54-04:00 "); !got.Equal(time.Date(2024, 8, 27, 5, 18, 54, 0, time.UTC)) {
		t.Fatalf("got %v", got)
	}
}

// TestProbeToleratesWronglyTypedManagerFields (review S-M2): a BMC that sends a
// wrongly typed LastResetTime or #Manager.Reset must not break discovery (and with it
// all polling): the restart is "not offered" and the last reset "unknown".
func TestProbeToleratesWronglyTypedManagerFields(t *testing.T) {
	cases := map[string]func(doc map[string]any){
		"last reset a number":  func(d map[string]any) { d["LastResetTime"] = 12345 },
		"last reset an object": func(d map[string]any) { d["LastResetTime"] = map[string]any{"x": 1} },
		"target a number":      func(d map[string]any) { actionsOf(d)["#Manager.Reset"] = map[string]any{"target": 5} },
		"allowable a string": func(d map[string]any) {
			actionsOf(d)["#Manager.Reset"] = map[string]any{"target": redfishmock.ManagerResetPath, "ResetType@Redfish.AllowableValues": "GracefulRestart"}
		},
		"reset action a string": func(d map[string]any) { actionsOf(d)["#Manager.Reset"] = "GracefulRestart" },
		"actions a list":        func(d map[string]any) { d["Actions"] = []any{1, 2} },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			s := mockFor(t, idrac9, redfishmock.WithManagerReset(0))
			raw, _ := s.Fixture(redfishmock.ManagerPath)
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			edit(doc)
			body, _ := json.Marshal(doc)
			s.SetOverlay(redfishmock.ManagerPath, string(body))
			caps, err := driverFor(t, s).Probe(testCtx(t))
			if err != nil {
				t.Fatalf("discovery broke: %v", err)
			}
			f := caps.Flags()
			if strings.HasPrefix(name, "last reset") {
				if !f.BMCLastReset.IsZero() || !f.ManagerReset {
					t.Fatalf("flags %+v", f)
				}
			} else if f.ManagerReset {
				t.Fatalf("a malformed action is offered: %+v", f)
			}
			if !f.SEL || f.BMCModel == "" {
				t.Fatalf("the rest of the manager was lost: %+v", f)
			}
			if _, err := OpenManagerResetter(testCtx(t), operatorConfig(s)); err == nil && !strings.HasPrefix(name, "last reset") {
				t.Fatal("a malformed action was accepted by the resetter")
			}
		})
	}
}

func actionsOf(d map[string]any) map[string]any {
	a, _ := d["Actions"].(map[string]any)
	return a
}

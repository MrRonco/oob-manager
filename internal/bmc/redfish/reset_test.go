package redfish

import (
	"errors"
	"net/http"
	"slices"
	"testing"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
)

func operatorConfig(s *redfishmock.Server) Config {
	cfg := configFor(s)
	cfg.Username, cfg.Password = redfishmock.OperatorUser, redfishmock.OperatorPassword
	return cfg
}

func TestIsResetActionURI(t *testing.T) {
	good := []string{
		"/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset",
		"/redfish/v1/Systems/1/Actions/ComputerSystem.Reset",
		"/redfish/v1/Systems/node_a-1/Actions/ComputerSystem.Reset",
	}
	bad := []string{
		"/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset/",
		"/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.SetDefaultBootOrder",
		"/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Manager.Reset",
		"/redfish/v1/Chassis/1/Actions/Chassis.Reset",
		"/redfish/v1/Systems/../Actions/ComputerSystem.Reset",
		"/redfish/v1/Systems/a/b/Actions/ComputerSystem.Reset",
		"/redfish/v1/Systems//Actions/ComputerSystem.Reset",
		"/redfish/v1/Systems/a%2f/Actions/ComputerSystem.Reset",
		"",
	}
	for _, p := range good {
		if !IsResetActionURI(p) {
			t.Errorf("refused %q", p)
		}
	}
	for _, p := range bad {
		if IsResetActionURI(p) {
			t.Errorf("accepted %q", p)
		}
	}
}

func TestResetterForceOffAndOn(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithPowerControl(0))
	r, err := OpenResetter(testCtx(t), operatorConfig(s))
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Allowed(); !slices.Contains(got, "PowerCycle") || !slices.Contains(got, "GracefulRestart") {
		t.Fatalf("allowed %v", got)
	}
	if st, err := r.PowerState(testCtx(t)); err != nil || st != bmc.PowerOn {
		t.Fatalf("state %v %v", st, err)
	}
	if err := r.Reset(testCtx(t), "ForceOff"); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.PowerState(testCtx(t)); st != bmc.PowerOff {
		t.Fatalf("after ForceOff: %v", st)
	}
	if err := r.Reset(testCtx(t), "On"); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	st := s.PowerStats()
	if want := []string{`{"ResetType":"ForceOff"}`, `{"ResetType":"On"}`}; !slices.Equal(st.Bodies, want) {
		t.Fatalf("bodies %q", st.Bodies)
	}
	if s.OtherWrites() != 0 || s.LiveSessions() != 0 {
		t.Fatalf("other writes %d live sessions %d", s.OtherWrites(), s.LiveSessions())
	}
}

func TestResetterRefusesBeforeSending(t *testing.T) {
	s := mockFor(t, idrac8, redfishmock.WithPowerControl(0))
	r, err := OpenResetter(testCtx(t), operatorConfig(s))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(testCtx(t)) }()
	// iDRAC8 does not offer PowerCycle; Nmi and PushPowerButton are not in the closed set.
	for _, rt := range []string{"PowerCycle", "GracefulRestart", "Nmi", "PushPowerButton", "", "forceoff"} {
		if err := r.Reset(testCtx(t), rt); !errors.Is(err, bmc.ErrUnsupported) {
			t.Errorf("%q: err = %v", rt, err)
		}
	}
	for _, req := range s.Requests() {
		if req.Method == http.MethodPost && req.Path == redfishmock.ResetActionPath {
			t.Fatalf("a refused reset reached the BMC")
		}
	}
}

func TestResetterBMCErrors(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithPowerControl(0))
	s.FailNextReset(http.StatusInternalServerError)
	r, err := OpenResetter(testCtx(t), operatorConfig(s))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(testCtx(t)) }()
	if rerr := r.Reset(testCtx(t), "ForceOff"); !errors.Is(rerr, bmc.ErrBMC) {
		t.Fatalf("err = %v", rerr)
	}
	// The read-only account is refused by the BMC (403).
	ro, err := OpenResetter(testCtx(t), configFor(s))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close(testCtx(t)) }()
	if err := ro.Reset(testCtx(t), "ForceOff"); !errors.Is(err, bmc.ErrAuth) {
		t.Fatalf("read-only: err = %v", err)
	}
}

func TestOpenResetterWithoutResetAction(t *testing.T) {
	sys := `{"@odata.id":"/redfish/v1/Systems/System.Embedded.1","PowerState":"On"}`
	s := mockFor(t, idrac9, redfishmock.WithOverlay(redfishmock.SystemPath, sys))
	if _, err := OpenResetter(testCtx(t), operatorConfig(s)); !errors.Is(err, bmc.ErrUnsupported) {
		t.Fatalf("err = %v", err)
	}
	if s.LiveSessions() != 0 {
		t.Fatal("session left open after a failed open")
	}
}

func TestOpenResetterRejectsForeignTarget(t *testing.T) {
	for _, target := range []string{
		"/redfish/v1/Systems/Other/Actions/ComputerSystem.Reset", // not under this system
		"/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Manager.Reset",
		"https://192.0.2.99/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset",
	} {
		sys := `{"@odata.id":"/redfish/v1/Systems/System.Embedded.1","PowerState":"On","Actions":{"#ComputerSystem.Reset":{"target":"` +
			target + `","ResetType@Redfish.AllowableValues":["ForceOff"]}}}`
		s := mockFor(t, idrac9, redfishmock.WithOverlay(redfishmock.SystemPath, sys))
		if _, err := OpenResetter(testCtx(t), operatorConfig(s)); !errors.Is(err, bmc.ErrUnsupported) {
			t.Errorf("%s: err = %v", target, err)
		}
	}
}

func TestOpenResetterLoginFailure(t *testing.T) {
	s := mockFor(t, idrac9)
	cfg := operatorConfig(s)
	cfg.Password = "wrong password"
	if _, err := OpenResetter(testCtx(t), cfg); !errors.Is(err, bmc.ErrAuth) {
		t.Fatalf("err = %v", err)
	}
	if _, err := OpenResetter(testCtx(t), Config{}); !errors.Is(err, bmc.ErrInvalidConfig) {
		t.Fatalf("empty config: %v", err)
	}
}

func TestResetterPowerStateTimeout(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithPowerControl(0))
	r, err := OpenResetter(testCtx(t), operatorConfig(s))
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close(testCtx(t))
	if _, err := r.PowerState(testCtx(t)); err == nil {
		t.Fatal("a closed resetter still reads")
	}
}

package dellredfish

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfish"
	"oob-manager/internal/bmc/redfishmock"
)

func TestProbeDetectsKVMLaunch(t *testing.T) {
	d, s := newDriver(t, idrac9, redfishmock.WithKVMSession())
	caps, err := d.Probe(ctx(t))
	if err != nil || !caps.Flags().KVMLaunch {
		t.Fatalf("KVMLaunch = %v, %v", caps.Flags().KVMLaunch, err)
	}
	if s.OtherWrites() != 0 || s.KVMStats().Launches != 0 {
		t.Fatal("detection must be read-only")
	}
	for _, fx := range []string{idrac9, idrac8} {
		d, _ := newDriver(t, fx) // no card service resource: feature absent
		caps, err := d.Probe(ctx(t))
		if err != nil || caps.Flags().KVMLaunch {
			t.Errorf("%s: KVMLaunch = %v, %v", fx, caps.Flags().KVMLaunch, err)
		}
	}
}

func TestProbeIgnoresForeignKVMTarget(t *testing.T) {
	doc := `{"Actions":{"#DelliDRACCardService.GetKVMSession":{"target":"/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset"}}}`
	d, _ := newDriver(t, idrac9, redfishmock.WithOverlay(redfishmock.KVMServicePath, doc))
	caps, err := d.Probe(ctx(t))
	if err != nil || caps.Flags().KVMLaunch {
		t.Fatalf("a target outside the card service must not count: %v %v", caps.Flags().KVMLaunch, err)
	}
}

func operatorConfig(s *redfishmock.Server) redfish.Config {
	return redfish.Config{Endpoint: s.URL(), Username: redfishmock.OperatorUser, Password: redfishmock.OperatorPassword,
		PinSHA256: s.PinSHA256(), Timeout: 2 * time.Second}
}

func TestLaunchKVMBuildsOneTimeURL(t *testing.T) {
	s := redfishmock.New(t, redfishmock.FixtureDir(t, idrac9), redfishmock.WithKVMSession(), redfishmock.WithTokenOnly())
	link, err := LaunchKVM(ctx(t), operatorConfig(s), "192.0.2.11")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(link.String(), "tmpkvm") {
		t.Fatal("the launch URL must be a redacting Secret")
	}
	u, err := url.Parse(link.Reveal())
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "https" || u.Host != "192.0.2.11" || u.Path != "/console" ||
		q.Get("username") != redfishmock.OperatorUser || q.Get("tempUsername") != "tmpkvm1" || q.Get("tempPassword") != "Tmp-pass-1" {
		t.Fatalf("URL = %s", link.Reveal())
	}
	st := s.KVMStats()
	if st.Launches != 1 || len(st.Types) != 1 || st.Types[0] != KVMSessionType {
		t.Errorf("kvm stats = %+v", st)
	}
	if s.LiveSessions() != 0 || s.OtherWrites() != 0 {
		t.Errorf("launcher must log out and write nothing else: live %d other %d", s.LiveSessions(), s.OtherWrites())
	}
}

func TestLaunchKVMFailures(t *testing.T) {
	s := redfishmock.New(t, redfishmock.FixtureDir(t, idrac9))
	if _, err := LaunchKVM(ctx(t), operatorConfig(s), "192.0.2.11"); !errors.Is(err, bmc.ErrUnsupported) {
		t.Errorf("no card service: %v", err)
	}
	k := redfishmock.New(t, redfishmock.FixtureDir(t, idrac9), redfishmock.WithKVMSession())
	ro := operatorConfig(k)
	ro.Username, ro.Password = redfishmock.User, redfishmock.Password
	if _, err := LaunchKVM(ctx(t), ro, "192.0.2.11"); !errors.Is(err, bmc.ErrAuth) {
		t.Errorf("read-only account: %v", err)
	}
	if _, err := LaunchKVM(ctx(t), redfish.Config{Endpoint: "http://x"}, "192.0.2.11"); !errors.Is(err, bmc.ErrInvalidConfig) {
		t.Errorf("bad config: %v", err)
	}
	if _, err := LaunchKVM(ctx(t), operatorConfig(k), ""); !errors.Is(err, bmc.ErrInvalidConfig) {
		t.Errorf("no host: %v", err)
	}
}

func TestKVMActionURIShape(t *testing.T) {
	ok := []string{
		"/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DelliDRACCardService/Actions/DelliDRACCardService.GetKVMSession",
		"/redfish/v1/Dell/Managers/iDRAC.Embedded.1/DelliDRACCardService/Actions/DelliDRACCardService.GetKVMSession",
	}
	bad := []string{
		"/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DelliDRACCardService/Actions/DelliDRACCardService.ResetToDefaults",
		"/redfish/v1/Managers/../Oem/Dell/DelliDRACCardService/Actions/DelliDRACCardService.GetKVMSession",
		"/redfish/v1/Managers/a/b/Oem/Dell/DelliDRACCardService/Actions/DelliDRACCardService.GetKVMSession",
		ok[0] + "?x=1", ok[0] + "/",
	}
	for _, p := range ok {
		if !IsKVMActionURI(p) {
			t.Errorf("%s refused", p)
		}
	}
	for _, p := range bad {
		if IsKVMActionURI(p) {
			t.Errorf("%s accepted", p)
		}
	}
	if validTemp("") || validTemp("has space") || validTemp(strings.Repeat("a", 129)) || !validTemp("Tmp-pass-1") {
		t.Error("validTemp")
	}
}

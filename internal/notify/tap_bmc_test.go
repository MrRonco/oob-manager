package notify

import (
	"strings"
	"testing"

	"oob-manager/internal/audit"
	"oob-manager/internal/fleet"
)

func TestTapMapsBMCRestarts(t *testing.T) {
	h := newTapHarness()
	cases := []struct {
		action, result, class, params string
		sev                           Severity
		recovery                      bool
		contains                      string
	}{
		{"bmc.reset", audit.ResultStarted, "", `{"reset_type":"GracefulRestart"}`, SeverityWarning, false, "alice requested a restart"},
		{"bmc.reset", audit.ResultError, "auth", "{}", SeverityWarning, false, "did not accept the restart requested by alice (auth)"},
		{"bmc.reset", audit.ResultDenied, "not_offered", `{"after_started":true}`, SeverityWarning, true, "was not sent (not_offered); nothing restarted"},
		{"bmc.reset", audit.ResultError, "auth", `{"after_started":true}`, SeverityWarning, true, "was not sent (auth)"},
		{"bmc.reset.verified", audit.ResultOK, "", `{"downtime_s":130}`, SeverityWarning, true, "answers again 130 s after"},
		{"bmc.reset.verified", audit.ResultOK, "", `{}`, SeverityWarning, true, "answers again after"},
		{"bmc.reset.verified", audit.ResultOK, "", `{"downtime_s":60,"restart_confirmed":true}`, SeverityWarning, true, "answers again 60 s after its restart"},
		{"bmc.reset.verified", audit.ResultOK, "", `{"downtime_s":60,"restart_confirmed":false}`, SeverityWarning, true, "did not confirm the restart"},
		{"bmc.reset.verified", audit.ResultError, "timeout", "{}", SeverityCritical, false, "did not answer by the deadline"},
		{"bmc.reset.verified", audit.ResultError, "config_changed", "{}", SeverityWarning, false, "no longer watched"},
		{"bmc.reset.verified", audit.ResultError, "unobserved", "{}", SeverityWarning, false, "could not be confirmed (unobserved)"},
	}
	for _, c := range cases {
		evs := h.send(c.action, c.result, c.class, c.params)
		if len(evs) != 1 || evs[0].Class != ClassBMC || evs[0].Severity != c.sev || evs[0].Recovery != c.recovery ||
			evs[0].Key != "bmc/srv-a" || !strings.Contains(evs[0].Message, c.contains) {
			t.Errorf("%s %s %s: %+v", c.action, c.result, c.class, evs)
		}
	}
	for _, quiet := range [][2]string{{"bmc.reset", audit.ResultDenied}, {"bmc.reset", audit.ResultOK}} {
		if evs := h.send(quiet[0], quiet[1], "cooldown", "{}"); len(evs) != 0 {
			t.Errorf("%v raised %+v", quiet, evs)
		}
	}
	if ClassBMC.Mutable() || ClassBMC.Label() != "BMC restarts" {
		t.Error("the bmc class is not suppressed by maintenance and has a label")
	}
	if _, err := ParseClass("bmc"); err != nil {
		t.Error("bmc is subscribable")
	}
}

// TestNoUnreachableDuringAnExpectedRestart: the restart window keeps the detector quiet
// even when the data turns stale; once the window ends without the BMC, the next pass
// reports it unreachable.
func TestNoUnreachableDuringAnExpectedRestart(t *testing.T) {
	d := NewDetector(0)
	t0 := fixedNow
	restarting := func(s *fleet.ServerState) { s.Restarting = true }
	if evs := run(d, healthy(t0), healthy(t0, down(t0), restarting)); len(evs) != 0 {
		t.Fatalf("an expected restart raised %+v", evs)
	}
	evs := run(d, healthy(t0, down(t0)))
	if len(evs) != 1 || evs[0].Class != ClassReachability || evs[0].Recovery {
		t.Fatalf("after the window: %+v", evs)
	}
}

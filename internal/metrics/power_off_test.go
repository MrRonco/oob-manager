package metrics

import (
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
)

// TestHealthStateOff (audit R2-01): a powered-off host is its own health state, below a
// critical sensor rollup and above everything else; stale data stays unknown.
func TestHealthStateOff(t *testing.T) {
	at := func(st bmc.PowerState, h bmc.Health) fleet.ServerState {
		return fleet.ServerState{HasSnapshot: true, Snapshot: bmc.NewSnapshot(bmc.SnapshotParams{PowerState: st, Health: h})}
	}
	cases := []struct {
		s     fleet.ServerState
		fresh bool
		want  string
	}{
		{at(bmc.PowerOff, bmc.HealthOK), true, "off"},
		{at(bmc.PowerPoweringOff, bmc.HealthWarning), true, "off"},
		{at(bmc.PowerOff, bmc.HealthCritical), true, "critical"},
		{at(bmc.PowerOn, bmc.HealthOK), true, "ok"},
		{at(bmc.PowerPoweringOn, bmc.HealthOK), true, "ok"},
		{at(bmc.PowerUnknown, bmc.HealthWarning), true, "warning"},
		{at(bmc.PowerOff, bmc.HealthOK), false, "unknown"},
	}
	for _, c := range cases {
		if got := healthState(c.s, c.fresh); got != c.want {
			t.Errorf("%s/%s fresh=%v: %s, want %s", c.s.Snapshot.PowerState(), c.s.Snapshot.Health(), c.fresh, got, c.want)
		}
	}
	for _, st := range serverHealthStates() {
		if st == "off" {
			return
		}
	}
	t.Fatal(`oob_server_health has no "off" state`)
}

func TestOffStateIsExposed(t *testing.T) {
	s := fleet.ServerState{ID: "box", Name: "Box", HasSnapshot: true, LastSuccess: t0,
		Snapshot: bmc.NewSnapshot(bmc.SnapshotParams{TakenAt: t0, PowerState: bmc.PowerOff, Health: bmc.HealthOK})}
	out := render(t, Config{Fleet: staticFleet{states: []fleet.ServerState{s}}, Now: func() time.Time { return t0 }})
	for _, want := range []string{`oob_server_health{server="box",state="off"} 1`, `oob_server_health{server="box",state="ok"} 0`,
		`oob_server_power_state{server="box",state="off"} 1`} {
		if !strings.Contains(out, want) {
			t.Errorf("scrape lacks %s", want)
		}
	}
	if strings.Contains(out, `oob_log_entries{log="sel",server="box",severity="off"}`) {
		t.Error(`log severities must not gain an "off" value`)
	}
}

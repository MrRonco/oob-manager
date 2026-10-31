package metrics

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/fleet"
)

// TestMaintenanceAndAckFamilies: oob_server_maintenance and its end time come from the
// maintenance hook (0 when none or until ended); oob_events_unacknowledged counts the
// warning and critical entries of both logs that are not acknowledged; health still
// reports the real verdict of a server in maintenance.
func TestMaintenanceAndAckFamilies(t *testing.T) {
	c, err := New(fullConfig(staticFleet{states: fixtureStates()}))
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.Render(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	until := t0.Add(2 * time.Hour).Unix()
	for _, want := range []string{
		`oob_server_maintenance{server="storage"} 0`,
		`oob_server_maintenance{server="edge"} 1`,
		`oob_server_maintenance{server="new"} 1`,
		`oob_server_maintenance_until_timestamp_seconds{server="storage"} 0`,
		`oob_server_maintenance_until_timestamp_seconds{server="edge"} ` + strconv.FormatFloat(float64(until), 'g', -1, 64),
		`oob_server_maintenance_until_timestamp_seconds{server="new"} 0`,
		`oob_events_unacknowledged{server="storage",severity="warning"} 1`,
		`oob_events_unacknowledged{server="storage",severity="critical"} 1`,
		`oob_server_health{server="storage",state="critical"} 1`,
	} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(text, `oob_events_unacknowledged{server="edge"`) {
		t.Error("a server without cached logs reports unacknowledged events")
	}
}

// TestNoMaintenanceOrAckSource: without the hooks, nobody is in maintenance and every
// warning or critical entry counts as unacknowledged.
func TestNoMaintenanceOrAckSource(t *testing.T) {
	c, err := New(Config{Fleet: staticFleet{states: fixtureStates()}, Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.Render(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{`oob_server_maintenance{server="edge"} 0`,
		`oob_server_maintenance_until_timestamp_seconds{server="edge"} 0`,
		`oob_events_unacknowledged{server="storage",severity="warning"} 2`,
		`oob_events_unacknowledged{server="storage",severity="critical"} 2`} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("missing %q", want)
		}
	}
}

func fixtureStates() []fleet.ServerState {
	return []fleet.ServerState{healthyState(), staleState(), neverPolled()}
}

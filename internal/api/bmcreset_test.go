package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
)

func TestBMCRestartInAPI(t *testing.T) {
	restarting := healthyState()
	restarting.Stale = true // the API keeps stale honest
	restarting.Restarting = true
	restarting.Restart = fleet.RestartWindow{Since: t0, Until: t0.Add(3 * time.Minute), By: "alice"}
	restarting.Capabilities = bmc.NewCapabilities(bmc.CapabilityParams{Flags: bmc.CapabilityFlags{ManagerReset: true,
		BMCLastReset: t0.Add(-time.Hour)}})
	restarting.HasCapabilities = true
	a := newTestAPI(t, Deps{
		Fleet: staticFleet{states: []fleet.ServerState{restarting, deadState()}, polled: true},
		BMCReset: func(id string) (BMCResetRecord, bool) {
			return BMCResetRecord{At: t0.Add(-2 * time.Hour), By: "bob", Result: "verified"}, id == "r730xd"
		},
	})
	list := decode[struct {
		Data []serverSummary `json:"data"`
	}](t, do(t, a, http.MethodGet, "/api/v1/servers", goodToken))
	if !list.Data[0].BMCRestarting || list.Data[1].BMCRestarting || !list.Data[0].Stale {
		t.Fatalf("summaries %+v", list.Data)
	}
	d := decode[serverDetail](t, do(t, a, http.MethodGet, "/api/v1/servers/r730xd", goodToken))
	b := d.BMC
	if !b.ResetSupported || !b.Restarting || b.RestartRequestedAt == nil || !b.RestartRequestedAt.Equal(t0) ||
		b.RestartDeadline == nil || !b.RestartDeadline.Equal(t0.Add(3*time.Minute)) ||
		b.LastResetTime == nil || !b.LastResetTime.Equal(t0.Add(-time.Hour)) ||
		b.LastAppReset == nil || b.LastAppReset.By != "bob" || b.LastAppReset.Result != "verified" {
		t.Fatalf("bmc %+v", b)
	}
	w := do(t, a, http.MethodGet, "/api/v1/servers/r240", goodToken)
	body := w.Body.String()
	for _, want := range []string{`"reset_supported":false`, `"restart_requested_at":null`, `"last_reset_time":null`,
		`"last_app_reset":null`} {
		if !strings.Contains(body, want) {
			t.Errorf("%s missing in %s", want, body)
		}
	}
}

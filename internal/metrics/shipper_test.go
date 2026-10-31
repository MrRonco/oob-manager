package metrics

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/fleet"
)

type shipperStats audit.ShipperStats

func (s shipperStats) Stats() audit.ShipperStats { return audit.ShipperStats(s) }

// TestShipperFamilies: TLS, pin mismatch, reconnects and the last success join the
// connected/queued/dropped families; a configured-but-disabled shipper (the zero
// ShipperStats from the switch) writes none of them.
func TestShipperFamilies(t *testing.T) {
	base := Config{Fleet: staticFleet{states: []fleet.ServerState{healthyState()}}, Now: func() time.Time { return t0 }}
	cfg := base
	cfg.Shipper = shipperStats{Active: true, TLS: true, PinMismatch: true, Reconnects: 4, LastSuccess: t0.Add(-time.Minute)}
	out := render(t, cfg)
	for _, want := range []string{"oob_audit_shipper_tls 1\n", "oob_audit_shipper_pin_mismatch 1\n",
		"oob_audit_shipper_reconnects_total 4\n", "oob_audit_shipper_connected 0\n",
		"oob_audit_shipper_last_success_timestamp_seconds " + strconv.FormatFloat(float64(t0.Add(-time.Minute).Unix()), 'g', -1, 64) + "\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	never := base
	never.Shipper = shipperStats{Active: true}
	if got := render(t, never); !strings.Contains(got, "oob_audit_shipper_last_success_timestamp_seconds 0\n") ||
		!strings.Contains(got, "oob_audit_shipper_tls 0\n") {
		t.Error("a shipper that never sent must read 0")
	}
	off := base
	off.Shipper = shipperStats{}
	out = render(t, off)
	if !strings.Contains(out, "oob_audit_shipper_enabled 0\n") || strings.Contains(out, "oob_audit_shipper_connected") {
		t.Error("disabled shipping: want only oob_audit_shipper_enabled 0")
	}
}

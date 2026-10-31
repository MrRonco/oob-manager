package notify

import (
	"strings"
	"testing"
)

// TestShipperTrustEvent: the GELF certificate events are critical trust events with no
// server (it is not a BMC, so maintenance never suppresses them), one key for problem
// and end; an expiry does not speak of an impostor.
func TestShipperTrustEvent(t *testing.T) {
	e := ShipperTrustEvent(ShipperMismatch, fixedNow)
	if e.Class != ClassTrust || e.Severity != SeverityCritical || e.ServerID != "" || e.Recovery ||
		!strings.Contains(e.Title, "mismatch") || !strings.Contains(e.Message, "paused") || strings.Contains(e.Message, "BMC") {
		t.Fatalf("mismatch event %+v", e)
	}
	x := ShipperTrustEvent(ShipperExpired, fixedNow)
	if x.Recovery || !strings.Contains(x.Title, "expired") || strings.Contains(x.Message, "Check the log server before") {
		t.Fatalf("expiry %+v", x)
	}
	for _, k := range []ShipperTrust{ShipperResolved, ShipperWithdrawn} {
		r := ShipperTrustEvent(k, fixedNow)
		if !r.Recovery || r.Key != e.Key || r.Severity != SeverityCritical {
			t.Fatalf("end %d: %+v", k, r)
		}
	}
	if !(Target{ID: "phone", Enabled: true, Classes: []Class{ClassTrust}}).Wants(e) {
		t.Fatal("a trust subscriber does not get it")
	}
}

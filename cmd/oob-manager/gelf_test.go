package main

import (
	"slices"
	"testing"

	"oob-manager/internal/config"
	"oob-manager/internal/integrations"
	"oob-manager/internal/notify"
)

func TestSelfPorts(t *testing.T) {
	cases := []struct {
		listen, public string
		want           []uint16
	}{
		{":8443", "https://oob.example.test/", []uint16{8443, 443}},
		{"192.0.2.20:8443", "https://192.0.2.20:8443/", []uint16{8443, 8443}},
		{"bad", "", nil},
		{":8443", "://", []uint16{8443}},
	}
	for _, tc := range cases {
		got := selfPorts(config.Config{Listen: tc.listen, PublicURL: tc.public})
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s %s: %v, want %v", tc.listen, tc.public, got, tc.want)
		}
	}
}

// TestShipperTrustBeforeNotifications: the shipper's trust hook is a no-op until the
// notifications service exists.
func TestShipperTrustBeforeNotifications(t *testing.T) {
	(&lateTap{}).shipperTrust(integrations.TrustMismatch)
	for c, want := range map[integrations.TrustChange]notify.ShipperTrust{integrations.TrustMismatch: notify.ShipperMismatch,
		integrations.TrustExpired: notify.ShipperExpired, integrations.TrustResolved: notify.ShipperResolved,
		integrations.TrustWithdrawn: notify.ShipperWithdrawn} {
		if got := shipperTrustKind(c); got != want {
			t.Errorf("%d: %d", c, got)
		}
	}
}

func TestPublicURLAddrsAndBMCAddrs(t *testing.T) {
	for _, u := range []string{"https://192.0.2.20:8443/", "://", ""} {
		if got := publicURLAddrs(u); got != nil {
			t.Errorf("%q resolved to %v", u, got)
		}
	}
	if got := publicURLAddrs("https://localhost:8443/"); len(got) == 0 {
		t.Error("localhost did not resolve")
	}
	if got := (&core{}).bmcAddrs(); got != nil {
		t.Fatalf("no registry, no servers, no database: %v", got)
	}
}

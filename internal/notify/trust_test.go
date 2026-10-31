package notify

import (
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/fleet"
)

func (h *tapHarness) trust(what string, ok bool) []Event {
	h.mu.Lock()
	h.evs = nil
	h.mu.Unlock()
	h.tap.Trust("srv-a", what, ok)
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Event(nil), h.evs...)
}

// TestTapTrustHook: S3's checks outside polling (Test connection, console connects)
// raise one critical trust event per cooldown and resolve only an open mismatch.
func TestTapTrustHook(t *testing.T) {
	h := newTapHarness()
	if evs := h.trust(TrustSSHKey, true); len(evs) != 0 {
		t.Fatalf("a passing check without a mismatch alerted: %+v", evs)
	}
	evs := h.trust(TrustSSHKey, false)
	if len(evs) != 1 || evs[0].Class != ClassTrust || evs[0].Severity != SeverityCritical || evs[0].Recovery ||
		evs[0].ServerName != "Name of srv-a" || evs[0].Key != "trust/srv-a/"+TrustSSHKey {
		t.Fatalf("mismatch: %+v", evs)
	}
	if evs := h.trust(TrustSSHKey, false); len(evs) != 0 {
		t.Fatalf("repeat inside the cooldown alerted: %+v", evs)
	}
	if evs := h.trust(TrustVNC, false); len(evs) != 1 {
		t.Fatalf("another check shares the cooldown: %+v", evs)
	}
	h.now = h.now.Add(trustCooldown + time.Second)
	if evs := h.trust(TrustSSHKey, false); len(evs) != 1 {
		t.Fatalf("repeat after the cooldown: %+v", evs)
	}
	if evs := h.trust(TrustSSHKey, true); len(evs) != 1 || !evs[0].Recovery {
		t.Fatalf("resolution: %+v", evs)
	}
	if evs := h.trust(TrustSSHKey, false); len(evs) != 1 {
		t.Fatalf("a new mismatch after the resolution was quiet: %+v", evs)
	}
	h.tap.Trust("", TrustSSHKey, false) // no server: ignored
}

// TestTapConsoleStopsAreTrustChecks: a serial connect refused for its host key and a
// VNC connect refused for its pin are mismatches; a session that ran resolves them.
func TestTapConsoleStopsAreTrustChecks(t *testing.T) {
	h := newTapHarness()
	cases := []struct {
		action, result, class string
		events                int
		recovery              bool
	}{
		{"console.serial.stop", audit.ResultOK, "", 0, false},           // nothing to resolve
		{"console.serial.stop", audit.ResultError, "timeout", 0, false}, // not a trust failure
		{"console.serial.stop", audit.ResultError, "host_key", 1, false},
		{"console.serial.stop", audit.ResultOK, "", 1, true},
		{"console.vnc.stop", audit.ResultError, "tls_pin", 1, false},
		{"console.vnc.stop", audit.ResultOK, "", 1, true},
	}
	for _, c := range cases {
		evs := h.send(c.action, c.result, c.class, "{}")
		if len(evs) != c.events || (c.events == 1 && (evs[0].Class != ClassTrust || evs[0].Recovery != c.recovery)) {
			t.Fatalf("%s %s %s: %+v", c.action, c.result, c.class, evs)
		}
	}
}

// TestTapKeepForgetsRemovedServers: a removed server's open mismatch is forgotten, so
// a server re-added with that id neither stays quiet nor sends a stray recovery.
func TestTapKeepForgetsRemovedServers(t *testing.T) {
	h := newTapHarness()
	if evs := h.trust(TrustSSHKey, false); len(evs) != 1 {
		t.Fatal(evs)
	}
	h.tap.Keep([]string{"srv-a"})
	if evs := h.trust(TrustSSHKey, false); len(evs) != 0 {
		t.Fatalf("a kept server lost its cooldown: %+v", evs)
	}
	h.tap.Keep([]string{"srv-b"})
	if evs := h.trust(TrustSSHKey, true); len(evs) != 0 {
		t.Fatalf("recovery for a forgotten mismatch: %+v", evs)
	}
	if evs := h.trust(TrustSSHKey, false); len(evs) != 1 {
		t.Fatalf("a re-added server stayed quiet: %+v", evs)
	}
	if got := trustServer("trust/srv-a"); got != "srv-a" {
		t.Fatalf("trustServer = %q", got)
	}
}

// TestPinMismatchPausedIsTrust: S3's poller pauses on a pin mismatch (PinMismatch,
// Paused); that alone raises the trust event, and the first good poll after a new pin
// is confirmed resolves it.
func TestPinMismatchPausedIsTrust(t *testing.T) {
	d := NewDetector(time.Minute)
	paused := healthy(fixedNow, func(s *fleet.ServerState) {
		s.PinMismatch, s.Paused, s.ConsecutiveFailures = true, true, 1
	})
	evs := run(d, healthy(fixedNow), paused)
	if len(evs) != 1 || evs[0].Class != ClassTrust || evs[0].Key != "trust/srv-a/"+TrustTLS {
		t.Fatalf("paused on a pin mismatch: %+v", evs)
	}
	if evs = run(d, healthy(fixedNow)); len(evs) != 1 || !evs[0].Recovery {
		t.Fatalf("resolved: %+v", evs)
	}
}

// TestDetectorForgetsServersThatLeaveTheFleet: a removed or disabled server is not in
// the fleet any more: it raises nothing (no reachability alert) and its state is
// dropped, so if it returns it starts from the healthy baseline.
func TestDetectorForgetsServersThatLeaveTheFleet(t *testing.T) {
	d := NewDetector(time.Minute)
	t0 := fixedNow
	other := healthy(t0, func(s *fleet.ServerState) { s.ID, s.Name = "srv-b", "Other" })
	gone := healthy(t0, down(t0.Add(-10*time.Minute)))
	if evs := d.Observe([]fleet.ServerState{gone, other}, t0); len(evs) != 1 || evs[0].Class != ClassReachability {
		t.Fatalf("down: %+v", evs)
	}
	// Disabled in Settings → Servers: only srv-b is polled now.
	for i := 1; i <= 10; i++ {
		if evs := d.Observe([]fleet.ServerState{other}, t0.Add(time.Duration(i)*time.Minute)); len(evs) != 0 {
			t.Fatalf("a server out of the fleet raised: %+v", evs)
		}
	}
	if _, kept := d.servers["srv-a"]; kept || len(d.servers) != 1 {
		t.Fatalf("stale detector state: %v", d.servers)
	}
	// Re-enabled and healthy: no stray "reachable again" for a down it never reported twice.
	if evs := d.Observe([]fleet.ServerState{healthy(t0.Add(11 * time.Minute)), other}, t0.Add(11*time.Minute)); len(evs) != 0 {
		t.Fatalf("re-added server: %+v", evs)
	}
}

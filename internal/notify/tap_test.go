package notify

import (
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/audit"
)

type tapHarness struct {
	mu  sync.Mutex
	evs []Event
	now time.Time
	tap *Tap
}

func newTapHarness() *tapHarness {
	h := &tapHarness{now: fixedNow}
	h.tap = NewTap(func(e Event) { h.mu.Lock(); h.evs = append(h.evs, e); h.mu.Unlock() },
		func(id string) string { return "Name of " + id }, func() time.Time { return h.now })
	return h
}

func (h *tapHarness) send(action, result, class string, params string) []Event {
	h.mu.Lock()
	h.evs = nil
	h.mu.Unlock()
	h.tap.Enqueue(audit.Message{Fields: map[string]any{"action": action, "result": result, "error_class": class,
		"server_id": "srv-a", "principal": "alice", "params": params}})
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Event(nil), h.evs...)
}

func TestTapTranslatesAuditRecords(t *testing.T) {
	h := newTapHarness()
	cases := []struct {
		action, result, class, params string
		want                          Class
		sev                           Severity
		contains                      string
	}{
		{"power.force_off", audit.ResultStarted, "", "{}", ClassPower, SeverityWarning, "alice requested power force off"},
		{"power.on", audit.ResultOK, "", "{}", ClassPower, SeverityInfo, "completed"},
		{"power.cycle", audit.ResultError, "timeout", "{}", ClassPower, SeverityWarning, "failed (timeout)"},
		{"fan.lease.create", audit.ResultOK, "", `{"pct":60}`, ClassFan, SeverityInfo, "at 60 %"},
		{"fan.lease.end", audit.ResultOK, "", "{}", ClassFan, SeverityInfo, "ended"},
		{"fan.lease.expire", audit.ResultOK, "", "{}", ClassFan, SeverityInfo, "(expired)"},
		{"fan.lease.create", audit.ResultError, "bmc", "{}", ClassFan, SeverityWarning, "failed (bmc)"},
		{"console.vnc.start", audit.ResultStarted, "", "", ClassConsole, SeverityWarning, "graphical console"},
		{"console.serial.start", audit.ResultStarted, "", "", ClassConsole, SeverityWarning, "serial console"},
		{"console.kvm_launch", audit.ResultOK, "", "", ClassConsole, SeverityWarning, "native BMC console"},
		{"console.vnc.takeover", audit.ResultOK, "", "", ClassConsole, SeverityWarning, "taken over"},
		{"admin.audit.verify", audit.ResultError, "tampered", "", ClassAudit, SeverityCritical, "hash chain"},
	}
	for _, c := range cases {
		evs := h.send(c.action, c.result, c.class, c.params)
		if len(evs) != 1 || evs[0].Class != c.want || evs[0].Severity != c.sev || !strings.Contains(evs[0].Message, c.contains) {
			t.Errorf("%s/%s: %+v", c.action, c.result, evs)
		}
	}
	ignored := [][2]string{{"power.on", audit.ResultDenied}, {"power.invalid", audit.ResultStarted},
		{"console.vnc.stop", audit.ResultOK}, {"console.vnc.start", audit.ResultDenied}, {"fan.lease.applied", audit.ResultOK},
		{"admin.audit.verify", audit.ResultOK}, {"auth.login", audit.ResultOK}, {"admin.user.create", audit.ResultOK}}
	for _, c := range ignored {
		if evs := h.send(c[0], c[1], "", ""); len(evs) != 0 {
			t.Errorf("%v raised %+v", c, evs)
		}
	}
	if !h.tap.Enqueue(audit.Message{}) {
		t.Error("Enqueue must always accept")
	}
}

func TestTapFailedLoginsAndLockout(t *testing.T) {
	h := newTapHarness()
	for i := range FailedLoginThreshold - 1 {
		if evs := h.send("auth.login", audit.ResultDenied, "password", ""); len(evs) != 0 {
			t.Fatalf("alert after %d failures", i+1)
		}
	}
	evs := h.send("auth.login", audit.ResultDenied, "totp", "")
	if len(evs) != 1 || evs[0].Class != ClassAuth || evs[0].Count != FailedLoginThreshold {
		t.Fatalf("threshold: %+v", evs)
	}
	if strings.Contains(evs[0].Message, "alice") {
		t.Fatal("failed-login alert names an account")
	}
	for range FailedLoginThreshold {
		if evs := h.send("auth.login", audit.ResultDenied, "password", ""); len(evs) != 0 {
			t.Fatal("alert inside the cooldown")
		}
	}
	// Failures older than the window do not count.
	h.now = h.now.Add(authCooldown + FailedLoginWindow)
	h.send("auth.login", audit.ResultDenied, "password", "")
	h.now = h.now.Add(FailedLoginWindow + time.Second)
	for range FailedLoginThreshold - 1 {
		if evs := h.send("auth.login", audit.ResultDenied, "password", ""); len(evs) != 0 {
			t.Fatal("stale failure counted")
		}
	}
	lock := h.send("auth.login", audit.ResultDenied, "password_locked_out", "")
	if len(lock) != 1 || lock[0].Title != "Sign-in lockout" {
		t.Fatalf("lockout: %+v", lock)
	}
	if again := h.send("auth.stepup", audit.ResultDenied, "totp_locked_out", ""); len(again) != 0 {
		t.Fatal("lockout repeated inside the cooldown")
	}
	if other := h.send("auth.login", audit.ResultDenied, "rate_limited", ""); len(other) != 0 {
		t.Fatal("rate limit counted as a failure")
	}
}

// TestTapSecurityAcceptances: an accepted risk is a security-class warning that names
// who accepted what and why; an acceptance that ended (by an admin or by the watch pass)
// is info. Refusals, errors and re-runs raise nothing.
func TestTapSecurityAcceptances(t *testing.T) {
	h := newTapHarness()
	accept := `{"check":"svc.ipmi","title":"IPMI over LAN","result":"warn","comment":"the UPS card polls it"}`
	evs := h.send("server.security.accept", audit.ResultOK, "", accept)
	if len(evs) != 1 || evs[0].Class != ClassSecurity || evs[0].Severity != SeverityWarning ||
		evs[0].Key != "security/accept/srv-a/svc.ipmi" || evs[0].Title != "Accepted risk: IPMI over LAN on Name of srv-a" ||
		!strings.Contains(evs[0].Message, "alice") || evs[0].ServerID != "srv-a" || evs[0].ServerName != "Name of srv-a" {
		t.Fatalf("accept: %+v", evs)
	}
	// The admin's free text travels in Detail, which only targets with IncludeDetail get.
	if strings.Contains(evs[0].Message, "the UPS card polls it") || len(evs[0].Detail) != 1 || evs[0].Detail[0] != "Comment: the UPS card polls it" {
		t.Fatalf("comment placement: message %q detail %v", evs[0].Message, evs[0].Detail)
	}
	ended := `{"check":"svc.ipmi","title":"IPMI over LAN","reason":"changed"}`
	h.tap.Enqueue(audit.Message{Fields: map[string]any{"action": "server.security.unaccept", "result": audit.ResultOK,
		"server_id": "srv-a", "principal": "system", "params": ended}})
	h.mu.Lock()
	evs = append([]Event(nil), h.evs...)
	h.mu.Unlock()
	if len(evs) != 2 || evs[1].Class != ClassSecurity || evs[1].Severity != SeverityInfo ||
		evs[1].Key != "security/unaccept/srv-a/svc.ipmi" || !strings.Contains(evs[1].Title, "Accepted risk ended: IPMI over LAN") ||
		!strings.Contains(evs[1].Message, "changed") || !strings.Contains(evs[1].Message, "system") {
		t.Fatalf("unaccept: %+v", evs)
	}
	// Without a title (an older row) the check ID names the finding.
	evs = h.send("server.security.accept", audit.ResultOK, "", `{"check":"svc.ipmi","comment":"c"}`)
	if len(evs) != 1 || evs[0].Title != "Accepted risk: svc.ipmi on Name of srv-a" {
		t.Fatalf("no title: %+v", evs)
	}
	for _, c := range [][2]string{{"server.security.accept", audit.ResultDenied}, {"server.security.accept", audit.ResultError},
		{"server.security.unaccept", audit.ResultDenied}, {"server.security.rerun", audit.ResultOK}, {"server.security.view", audit.ResultDenied}} {
		if evs := h.send(c[0], c[1], "stepup_required", accept); len(evs) != 0 {
			t.Errorf("%v raised %+v", c, evs)
		}
	}
}

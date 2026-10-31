package notify

import (
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
)

type stateOpt func(*fleet.ServerState)

func healthy(at time.Time, opts ...stateOpt) fleet.ServerState {
	s := fleet.ServerState{ID: "srv-a", Name: "Storage node", HasSnapshot: true, LastAttempt: at, LastSuccess: at,
		StaleAfter: 3 * time.Minute,
		Snapshot: bmc.NewSnapshot(bmc.SnapshotParams{Health: bmc.HealthOK, PowerTelemetry: bmc.PowerTelemetryAvailable,
			PSUs: []bmc.PSU{{ID: "1", Health: bmc.HealthOK}, {ID: "2", Health: bmc.HealthOK}}})}
	for _, o := range opts {
		o(&s)
	}
	return s
}

func withHealth(h bmc.Health) stateOpt {
	return func(s *fleet.ServerState) {
		s.Snapshot = bmc.NewSnapshot(bmc.SnapshotParams{Health: h, PowerTelemetry: bmc.PowerTelemetryAvailable,
			PSUs: s.Snapshot.PSUs()})
	}
}

func withPSUs(hs ...bmc.Health) stateOpt {
	return func(s *fleet.ServerState) {
		var ps []bmc.PSU
		for i, h := range hs {
			ps = append(ps, bmc.PSU{ID: string(rune('1' + i)), Health: h})
		}
		s.Snapshot = bmc.NewSnapshot(bmc.SnapshotParams{Health: bmc.HealthOK, PowerTelemetry: bmc.PowerTelemetryAvailable, PSUs: ps})
	}
}

func withSEL(entries ...bmc.Event) stateOpt {
	return func(s *fleet.ServerState) { s.SEL, s.HasSEL = bmc.NewEventLog("sel", entries, true), true }
}

func down(since time.Time) stateOpt {
	return func(s *fleet.ServerState) {
		s.Stale, s.ConsecutiveFailures, s.FailingSince, s.LastError = true, 4, since, bmc.ClassTimeout
	}
}

// run feeds one state per step (one step = 30 s) and returns all events.
func run(d *Detector, states ...fleet.ServerState) []Event {
	var out []Event
	for i, s := range states {
		out = append(out, d.Observe([]fleet.ServerState{s}, fixedNow.Add(time.Duration(i)*30*time.Second))...)
	}
	return out
}

func TestHealthDebounceAndRecovery(t *testing.T) {
	d := NewDetector(time.Minute)
	t0 := fixedNow
	// One odd reading (30 s) is not reported.
	if evs := run(d, healthy(t0), healthy(t0, withHealth(bmc.HealthCritical)), healthy(t0)); len(evs) != 0 {
		t.Fatalf("blip reported: %+v", evs)
	}
	d = NewDetector(time.Minute)
	evs := run(d, healthy(t0), healthy(t0, withHealth(bmc.HealthCritical)), healthy(t0, withHealth(bmc.HealthCritical)),
		healthy(t0, withHealth(bmc.HealthCritical)), healthy(t0, withHealth(bmc.HealthCritical)))
	if len(evs) != 1 || evs[0].Class != ClassHealth || evs[0].Severity != SeverityCritical || evs[0].Recovery {
		t.Fatalf("problem: %+v", evs)
	}
	evs = run(d, healthy(t0), healthy(t0), healthy(t0))
	if len(evs) != 1 || !evs[0].Recovery || evs[0].Severity != SeverityCritical || !strings.Contains(evs[0].Message, "was Critical") {
		t.Fatalf("recovery: %+v", evs)
	}
	if evs = run(d, healthy(t0), healthy(t0)); len(evs) != 0 {
		t.Fatalf("duplicate: %+v", evs)
	}
}

func TestHealthProblemAtStartupAndUnknownIgnored(t *testing.T) {
	d := NewDetector(time.Second)
	evs := run(d, healthy(fixedNow, withHealth(bmc.HealthWarning)), healthy(fixedNow, withHealth(bmc.HealthWarning)))
	if len(evs) != 1 || evs[0].Severity != SeverityWarning {
		t.Fatalf("startup problem: %+v", evs)
	}
	unknown := fleet.ServerState{ID: "srv-b", Name: "B", HasSnapshot: true, LastAttempt: fixedNow, LastSuccess: fixedNow,
		StaleAfter: time.Hour}
	if evs := run(NewDetector(time.Second), unknown, unknown, unknown); len(evs) != 0 {
		t.Fatalf("unknown health reported: %+v", evs)
	}
}

func TestReachabilityStaleAndRecovered(t *testing.T) {
	d := NewDetector(time.Minute)
	t0 := fixedNow
	never := fleet.ServerState{ID: "srv-a", Name: "Storage node", StaleAfter: 3 * time.Minute, Stale: true}
	if evs := run(d, never, never); len(evs) != 0 {
		t.Fatalf("unpolled server judged: %+v", evs)
	}
	evs := run(d, healthy(t0), healthy(t0, down(t0)))
	if len(evs) != 1 || evs[0].Class != ClassReachability || evs[0].Recovery || !strings.Contains(evs[0].Message, "timeout") {
		t.Fatalf("down: %+v", evs)
	}
	if evs = run(d, healthy(t0, down(t0))); len(evs) != 0 {
		t.Fatalf("repeated: %+v", evs)
	}
	evs = run(d, healthy(t0))
	if len(evs) != 1 || !evs[0].Recovery || evs[0].Class != ClassReachability {
		t.Fatalf("recovery: %+v", evs)
	}
	// Never had a snapshot: judged once failing longer than the stale threshold.
	d = NewDetector(time.Minute)
	failing := fleet.ServerState{ID: "c", Name: "C", LastAttempt: t0, FailingSince: t0, StaleAfter: time.Minute, Stale: true}
	if evs := d.Observe([]fleet.ServerState{failing}, t0.Add(30*time.Second)); len(evs) != 0 {
		t.Fatal("reported before the threshold")
	}
	if evs := d.Observe([]fleet.ServerState{failing}, t0.Add(2*time.Minute)); len(evs) != 1 {
		t.Fatalf("not reported after the threshold: %+v", evs)
	}
}

func TestTrustMismatch(t *testing.T) {
	d := NewDetector(time.Minute)
	mism := healthy(fixedNow, func(s *fleet.ServerState) { s.LastError, s.ConsecutiveFailures = bmc.ClassTLS, 1 })
	evs := run(d, healthy(fixedNow), mism)
	if len(evs) != 1 || evs[0].Class != ClassTrust || evs[0].Severity != SeverityCritical {
		t.Fatalf("mismatch: %+v", evs)
	}
	evs = run(d, healthy(fixedNow))
	if len(evs) != 1 || !evs[0].Recovery {
		t.Fatalf("resolved: %+v", evs)
	}
	if e := TrustEvent("s", "S", "SSH host key", false, fixedNow); !strings.Contains(e.Title, "SSH host key mismatch") {
		t.Fatalf("hook: %+v", e)
	}
}

func TestPSURedundancy(t *testing.T) {
	d := NewDetector(time.Minute)
	t0 := fixedNow
	lost := healthy(t0, withPSUs(bmc.HealthOK, bmc.HealthCritical))
	evs := run(d, healthy(t0), lost, lost, lost)
	var psu []Event
	for _, e := range evs {
		if e.Class == ClassPSU {
			psu = append(psu, e)
		}
	}
	if len(psu) != 1 || psu[0].Recovery || !strings.Contains(psu[0].Message, "Only 1 of 2") {
		t.Fatalf("lost: %+v", evs)
	}
	// A pulled PSU (2 → 1 reported) is still a loss of redundancy.
	evs = run(d, healthy(t0, withPSUs(bmc.HealthOK)), healthy(t0, withPSUs(bmc.HealthOK)), healthy(t0, withPSUs(bmc.HealthOK)))
	for _, e := range evs {
		if e.Class == ClassPSU {
			t.Fatalf("pulled PSU reported as restored: %+v", e)
		}
	}
	evs = run(d, healthy(t0), healthy(t0), healthy(t0))
	if len(evs) != 1 || !evs[0].Recovery {
		t.Fatalf("restored: %+v", evs)
	}
	single := healthy(t0, withPSUs(bmc.HealthCritical))
	if evs := run(NewDetector(time.Second), single, single, single); len(evs) != 1 || evs[0].Class != ClassHealth {
		t.Fatalf("single PSU server: %+v", evs)
	}
}

func TestNewLogEntries(t *testing.T) {
	d := NewDetector(time.Minute)
	t0 := fixedNow
	old := bmc.Event{ID: "1", Created: t0.Add(-time.Hour), Severity: bmc.SeverityCritical, Message: "old fault"}
	base := healthy(t0, withSEL(old))
	if evs := run(d, base); len(evs) != 0 {
		t.Fatalf("history reported: %+v", evs)
	}
	newer := []bmc.Event{
		{ID: "4", Created: t0.Add(3 * time.Minute), Severity: bmc.SeverityOK, Message: "ok entry"},
		{ID: "3", Created: t0.Add(2 * time.Minute), Severity: bmc.SeverityWarning, Message: "fan slow"},
		{ID: "2", Created: t0.Add(time.Minute), Severity: bmc.SeverityCritical, Message: "PSU lost\r\ninput"},
		old,
	}
	evs := run(d, healthy(t0, withSEL(newer...)))
	if len(evs) != 1 || evs[0].Count != 2 || evs[0].Severity != SeverityCritical || len(evs[0].Detail) != 2 {
		t.Fatalf("new entries: %+v", evs)
	}
	if strings.Contains(evs[0].Message, "PSU lost") || strings.ContainsAny(evs[0].Detail[1], "\r\n") {
		t.Fatalf("BMC text in the message or unsanitised detail: %+v", evs[0])
	}
	if evs := run(d, healthy(t0, withSEL(newer...))); len(evs) != 0 {
		t.Fatalf("re-reported: %+v", evs)
	}
	// A cleared log restarts its IDs; newer entries still count.
	cleared := bmc.Event{ID: "1", Created: t0.Add(10 * time.Minute), Severity: bmc.SeverityWarning, Message: "after clear"}
	if evs := run(d, healthy(t0, withSEL(cleared))); len(evs) != 1 || evs[0].Count != 1 {
		t.Fatalf("after clear: %+v", evs)
	}
}

func TestTrackerObserve(t *testing.T) {
	tr := tracker{confirmed: "a"}
	tr, _, ch := tr.observe("b", fixedNow, time.Minute)
	if ch {
		t.Fatal("changed before debounce")
	}
	tr, _, ch = tr.observe("c", fixedNow.Add(50*time.Second), time.Minute)
	if ch || tr.candidate != "c" {
		t.Fatal("candidate not replaced")
	}
	_, from, ch := tr.observe("c", fixedNow.Add(111*time.Second), time.Minute)
	if !ch || from != "a" {
		t.Fatalf("change %v from %q", ch, from)
	}
}

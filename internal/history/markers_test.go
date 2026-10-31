package history

import (
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/store"
)

func TestFromLogs(t *testing.T) {
	entries := []LogEntry{
		{Event: bmc.Event{Created: at(1), Severity: bmc.SeverityCritical, Message: "PSU 1 lost input"}, Log: "System Event Log"},
		{Event: bmc.Event{Created: at(2), Severity: bmc.SeverityWarning, Message: "=cmd|' /C calc'!A0"}, Acked: true},
		{Event: bmc.Event{Created: at(3), Severity: bmc.SeverityOK, Message: "ok"}},
		{Event: bmc.Event{Severity: bmc.SeverityCritical, Message: "no time"}},
		{Event: bmc.Event{Created: at(30), Severity: bmc.SeverityCritical, Message: "after"}},
	}
	got := FromLogs(entries, at(0), at(24))
	if len(got) != 2 || !got[0].Critical || got[0].Log != "System Event Log" || got[1].Critical || !got[1].Acked ||
		got[1].Text != "=cmd|' /C calc'!A0" || got[0].Kind != MarkLog {
		t.Fatalf("FromLogs = %+v", got)
	}
}

func rec(h int, action, result, who string) store.AuditRecord {
	return store.AuditRecord{TS: at(h), Action: action, Result: result, Principal: who}
}

func TestFromAudit(t *testing.T) {
	recs := []store.AuditRecord{
		rec(5, "server.maintenance.end", "ok", "alice"), // a window that started before the range
		rec(2, "power.graceful_restart", "started", "alice"),
		rec(2, "power.graceful_restart", "ok", "alice"), // only the request is drawn
		rec(3, "fan.lease.create", "ok", "bob"),
		rec(3, "fan.lease.create", "denied", "eve"),
		rec(4, "fan.lease.end", "ok", "bob"),
		rec(6, "fan.lease.expire", "ok", "system"),
		rec(7, "bmc.reset", "started", "alice"),
		rec(8, "bmc.reset.verified", "ok", "system"),
		rec(9, "bmc.reset.verified", "error", "system"),
		rec(10, "server.maintenance.start", "ok", "alice"),
		rec(11, "server.maintenance.end", "ok", "alice"),
		rec(12, "server.maintenance.start", "ok", "alice"), // still open at the end
		rec(40, "power.on", "started", "alice"),            // after the range
		rec(1, "app.start", "ok", "system"),
	}
	marks, spans := FromAudit(recs, at(0), at(24))
	var texts []string
	for _, m := range marks {
		texts = append(texts, m.Text)
	}
	want := []string{"Graceful restart requested by alice", "Fan lease started by bob", "Fan lease ended by bob",
		"Fan lease expired", "BMC restart requested by alice", "BMC back after its restart", "BMC did not come back in time"}
	if strings.Join(texts, "|") != strings.Join(want, "|") {
		t.Fatalf("markers:\n got %q\nwant %q", texts, want)
	}
	if marks[0].Kind != MarkPower || marks[1].Kind != MarkFan || marks[4].Kind != MarkBMC {
		t.Errorf("kinds = %+v", marks)
	}
	wantSpans := []Span{{From: at(0), To: at(5)}, {From: at(10), To: at(11)}, {From: at(12), To: at(24), Open: true}}
	if len(spans) != 3 || spans[0] != wantSpans[0] || spans[1] != wantSpans[1] || spans[2] != wantSpans[2] {
		t.Errorf("spans = %+v", spans)
	}
	if len(AuditActions()) > store.MaxAuditFilterActions {
		t.Error("too many overlay actions for one query")
	}
}

func TestCollectCapsTheOldest(t *testing.T) {
	var many []Marker
	for i := 0; i < MaxMarkers+5; i++ {
		many = append(many, Marker{At: at(0).Add(time.Duration(MaxMarkers+5-i) * time.Minute), Text: "m"})
	}
	got := Collect([]Span{{From: at(1), To: at(2)}}, many[:10], many[10:])
	if len(got.Marks) != MaxMarkers || got.More != 5 || len(got.Spans) != 1 {
		t.Fatalf("Collect: %d marks, more %d", len(got.Marks), got.More)
	}
	if !got.Marks[0].At.Equal(at(0).Add(6*time.Minute)) || got.Marks[0].At.After(got.Marks[1].At) {
		t.Errorf("not the newest, oldest first: %v %v", got.Marks[0].At, got.Marks[1].At)
	}
}

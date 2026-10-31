package notify

import (
	"strings"
	"testing"
	"time"

	"oob-manager/internal/audit"
)

func integrationsMessage(action, result, params string) audit.Message {
	return audit.Message{Fields: map[string]any{"action": action, "result": result, "principal": "alice", "params": params}}
}

// TestTapIntegrationsChange: a change of the GELF target is notified: critical when
// shipping goes off, TLS is dropped or the address moves; a warning otherwise; nothing
// for a refused change.
func TestTapIntegrationsChange(t *testing.T) {
	var got []Event
	tap := NewTap(func(e Event) { got = append(got, e) }, nil, func() time.Time { return fixedNow })
	cases := []struct {
		params string
		want   Severity
	}{
		{`{"changes":[{"field":"gelf.enabled","before":"on","after":"off"}]}`, SeverityCritical},
		{`{"changes":[{"field":"gelf.transport","before":"tls","after":"tcp"}]}`, SeverityCritical},
		{`{"changes":[{"field":"gelf.address","before":"192.0.2.30:12201","after":"192.0.2.31:12201"}]}`, SeverityCritical},
		{`{"changes":[{"field":"gelf.server_name","before":"","after":"logs.example.test"}]}`, SeverityCritical},
		{`{"changes":[{"field":"gelf.pin_sha256","before":"aa","after":"bb"}]}`, SeverityCritical},
		{`{"changes":[{"field":"gelf.enabled","before":"off","after":"on"},{"field":"gelf.transport","before":"tcp","after":"tls"}]}`, SeverityWarning},
		{`not json`, SeverityWarning},
	}
	for i, c := range cases {
		tap.Enqueue(integrationsMessage("admin.integrations.update", audit.ResultOK, c.params))
		if len(got) != i+1 || got[i].Severity != c.want || got[i].Class != ClassAudit || !strings.Contains(got[i].Title, "alice") {
			t.Fatalf("case %d: %+v", i, got)
		}
	}
	if !strings.Contains(got[2].Message, "192.0.2.30:12201 → 192.0.2.31:12201") {
		t.Fatalf("message %q", got[2].Message)
	}
	tap.Enqueue(integrationsMessage("admin.integrations.reset", audit.ResultOK, `{"changes":[{"field":"gelf.enabled","before":"on","after":"off"}]}`))
	tap.Enqueue(integrationsMessage("admin.integrations.update", audit.ResultDenied, `{}`))
	if len(got) != len(cases)+1 || got[len(cases)].Severity != SeverityCritical {
		t.Fatalf("reset/denied %+v", got[len(cases):])
	}
}

// TestTapIntegrationsFirstSetup: turning shipping on together with its first address,
// pin or server name (each going from empty to a value) is a warning: nothing was shipped
// or trusted before, so nothing was redirected. A value replacing another value stays
// critical, and so does a first pin while shipping was already on.
func TestTapIntegrationsFirstSetup(t *testing.T) {
	var got []Event
	tap := NewTap(func(e Event) { got = append(got, e) }, nil, func() time.Time { return fixedNow })
	on := `{"field":"gelf.enabled","before":"off","after":"on"}`
	cases := []struct {
		name, changes string
		want          Severity
	}{
		{"first confirm with the address", on + `,{"field":"gelf.address","before":"","after":"192.0.2.30:6514"},` +
			`{"field":"gelf.transport","before":"tcp","after":"tls"},{"field":"gelf.server_name","before":"","after":"logs.example.test"},` +
			`{"field":"gelf.pin_sha256","before":"","after":"aa"}`, SeverityWarning},
		{"first confirm of a saved draft", on + `,{"field":"gelf.transport","before":"tcp","after":"tls"},` +
			`{"field":"gelf.pin_sha256","before":"","after":"aa"}`, SeverityWarning},
		{"pin replaced while enabling", on + `,{"field":"gelf.pin_sha256","before":"aa","after":"bb"}`, SeverityCritical},
		{"draft address replaced while enabling", on + `,{"field":"gelf.address","before":"192.0.2.30:6514","after":"192.0.2.31:6514"}`, SeverityCritical},
		{"name replaced while enabling", on + `,{"field":"gelf.server_name","before":"a.example.test","after":"b.example.test"}`, SeverityCritical},
		{"first pin while shipping is on", `{"field":"gelf.transport","before":"tcp","after":"tls"},{"field":"gelf.pin_sha256","before":"","after":"aa"}`, SeverityCritical},
		{"first address while shipping stays off", `{"field":"gelf.address","before":"","after":"192.0.2.30:6514"}`, SeverityCritical},
	}
	for i, c := range cases {
		tap.Enqueue(integrationsMessage("admin.integrations.update", audit.ResultOK, `{"changes":[`+c.changes+`]}`))
		if len(got) != i+1 || got[i].Severity != c.want {
			t.Fatalf("%s: %+v", c.name, got[len(got)-1])
		}
	}
}

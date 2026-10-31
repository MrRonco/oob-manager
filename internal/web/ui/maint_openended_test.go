package ui

import (
	"context"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/authz"
	"oob-manager/internal/maint"
)

// TestOpenEndedMaintenanceWarning: an "until I end it" window shows on Overview as an
// "Open-ended maintenance" warning once it has lasted 24 h (not before); timed windows
// never do; the reason is escaped.
func TestOpenEndedMaintenanceWarning(t *testing.T) {
	e := newMaintEnv(t)
	ctx := context.Background()
	a := actorFor(t, e.settingsEnv, "morgan")
	if _, err := e.m.Start(ctx, a, "r730xd", maint.StartRequest{Reason: "rack <move>"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Start(ctx, a, "r240", maint.StartRequest{Reason: "firmware", Duration: maint.MaxWindow}); err != nil {
		t.Fatal(err)
	}
	result(e.adminClient().get("/")).lacks(t, "Open-ended maintenance")
	e.clock.Advance(maint.OpenEndedAfter + time.Minute)
	op := e.userClient(t, "oscar", authz.RoleOperator, "192.0.2.30") // sessions of a day ago have expired
	page := result(op.get("/"))
	page.contains(t, `<p class="alert a-warn" role="status">`, `<span class="alert-b"><strong>Open-ended maintenance:</strong>`,
		"(morgan: rack &lt;move&gt;)", "paused for over 24 h").lacks(t, "rack <move>")
	body := page.rec.Body.String()
	warn := body[strings.Index(body, "Open-ended maintenance:"):]
	warn = warn[:strings.Index(warn, "</p>")]
	if !strings.Contains(warn, `href="/servers/r730xd"`) || strings.Contains(warn, "r240") {
		t.Fatalf("warning lists %q", warn)
	}
	if err := e.m.End(ctx, a, "r730xd"); err != nil {
		t.Fatal(err)
	}
	result(op.get("/")).lacks(t, "Open-ended maintenance")
}

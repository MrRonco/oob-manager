package ui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

func TestFoldRepeats(t *testing.T) {
	es := []bmc.Event{ // newest first, as the BMC returns them
		{ID: "5", Message: "The previous log entry was repeated 22 times.", MessageID: "LOG007"},
		{ID: "4", Message: "Unable to log in for root from 192.0.2.77.", Severity: bmc.SeverityWarning},
		{ID: "3", Message: "Clock synchronized."},
		{ID: "2", Message: "The previous log entry was repeated 1 times."},
		{ID: "1", Message: "Fan 1 low.", Severity: bmc.SeverityCritical},
		{ID: "0", Message: "The previous log entry was repeated 2 times."},
	}
	got := foldRepeats(es)
	if len(got) != 4 {
		t.Fatalf("folded = %+v", got)
	}
	if got[0].Event.ID != "4" || got[0].Repeat != 23 {
		t.Errorf("first = %+v, want record 4 x23", got[0])
	}
	if got[1].Repeat != 0 || got[2].Event.ID != "1" || got[2].Repeat != 2 {
		t.Errorf("rest = %+v", got[1:])
	}
	if got[3].Event.ID != "0" {
		t.Errorf("a trailing marker with nothing older to attach to stays a row: %+v", got[3])
	}
}

func TestLogSeverityInfoIsNotOK(t *testing.T) {
	if h := logSeverity(bmc.SeverityOK); h.Label != "Info" || h.Class != "info" {
		t.Fatalf("informational entry = %+v", h)
	}
	if h := logSeverity(bmc.SeverityWarning); h.Class != "warn" {
		t.Fatalf("warning = %+v", h)
	}
}

func eventsFleet(h *harness) {
	now := h.clock.Now()
	h.fleet.logs["r730xd/sel"] = bmc.NewEventLog("", []bmc.Event{
		{ID: "9", Created: now.Add(-1 * time.Hour), Message: "The previous log entry was repeated 3 times.", MessageID: "LOG007"},
		{ID: "8", Created: now.Add(-2 * time.Hour), Message: "Power supply 2 input lost.", MessageID: "PSU0003", Severity: bmc.SeverityWarning},
		{ID: "7", Created: now.Add(-3 * time.Hour), Message: "Clock synchronized.", Severity: bmc.SeverityOK},
		{ID: "6", Created: now.Add(-10 * 24 * time.Hour), Message: "The chassis is open.", Severity: bmc.SeverityCritical},
	}, true)
	h.fleet.logs["r240/sel"] = bmc.NewEventLog("", []bmc.Event{
		{ID: "1", Created: now.Add(-30 * time.Hour), Message: "Login lockout alert.", Severity: bmc.SeverityWarning},
	}, true)
}

func TestEventsDefaultIsWarningAndWorseOverSevenDays(t *testing.T) {
	h, c := signedIn(t)
	eventsFleet(h)
	r := result(c.get("/events")).status(t, http.StatusOK)
	r.contains(t, "Power supply 2 input lost.", `<span class="rep">×4</span>`, "Login lockout alert.",
		"Today, Oct 20", "Yesterday, Oct 19", `class="ev-warn"`, `data-label="Message"`,
		"1 info entry hidden", `href="/events?severity=all"`).
		lacks(t, "Clock synchronized.", "The chassis is open.", "repeated 3 times")
}

func TestEventsFilters(t *testing.T) {
	h, c := signedIn(t)
	eventsFleet(h)
	result(c.get("/events?severity=all&range=all")).contains(t, "Clock synchronized.", "The chassis is open.",
		`<use href="#i-info"/></svg> Info`)
	result(c.get("/events?severity=all&range=24h")).contains(t, "Clock synchronized.").lacks(t, "Login lockout alert.")
	result(c.get("/events?server=r240&severity=all")).contains(t, "Login lockout alert.").lacks(t, "Power supply 2")
	result(c.get("/events?q=POWER+supply&severity=all")).contains(t, "Power supply 2").lacks(t, "Login lockout")
	result(c.get("/events?severity=critical&range=30d")).contains(t, "The chassis is open.").lacks(t, "Power supply 2")
	for _, q := range []string{"server=nope", "server=../x", "range=1y", "severity=info", "q=" + url.QueryEscape("\x00"),
		"q=" + strings.Repeat("x", 65)} {
		result(c.get("/events?"+q)).status(t, http.StatusBadRequest)
	}
}

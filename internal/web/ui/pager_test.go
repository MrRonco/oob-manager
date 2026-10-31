package ui

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

// warningLog is n warning entries, newest first, within the last day.
func warningLog(now time.Time, n int) bmc.EventLog {
	entries := make([]bmc.Event, 0, n)
	for i := range n {
		entries = append(entries, bmc.Event{ID: fmt.Sprint(i + 1), Created: now.Add(-time.Duration(i+1) * time.Minute),
			Message: fmt.Sprintf("Synthetic warning %d", i+1), MessageID: "SYN0001", Severity: bmc.SeverityWarning})
	}
	return bmc.NewEventLog("", entries, true)
}

// TestPagerLandmarksAreUnique (audit R2-25): a list longer than one page renders a pager
// above and below the table; the two navigation landmarks carry different labels, so
// axe's landmark-unique rule passes on Events and on a server's Logs.
func TestPagerLandmarksAreUnique(t *testing.T) {
	h, c := signedIn(t)
	h.fleet.logs["r730xd/sel"] = warningLog(h.clock.Now(), 60)
	for _, tc := range []struct{ path, label string }{
		{"/events", "Event pages"}, {"/servers/r730xd/events", "Log pages"},
	} {
		body := result(c.get(tc.path)).status(t, http.StatusOK).rec.Body.String()
		top, bottom := strings.Count(body, `aria-label="`+tc.label+`"`), strings.Count(body, `aria-label="`+tc.label+`, bottom"`)
		if top != 1 || bottom != 1 || strings.Count(body, `class="pager"`) != 2 {
			t.Fatalf("%s: %d top and %d bottom pager landmarks (%d pagers)", tc.path, top, bottom, strings.Count(body, `class="pager"`))
		}
	}
	// One page: no pager at all.
	h.fleet.logs["r730xd/sel"] = warningLog(h.clock.Now(), 3)
	result(c.get("/events")).status(t, http.StatusOK).lacks(t, `class="pager"`)
}

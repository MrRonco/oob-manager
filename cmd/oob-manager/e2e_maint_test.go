//go:build e2e

package main

import (
	"html"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"oob-manager/internal/notify"
)

var e2eRefRE = regexp.MustCompile(`name="ref" value="([^"]+)"`)

// checkMaintenance drives maintenance mode, notes and acknowledgements through the real
// stack (tech_doc §28): a window started on the R730XD (shown on the server page, the
// Overview and the API; one "started" message to the file webhook), a note added and
// pinned, every critical SEL entry acknowledged at once (the API reports the acks), the
// window ended ("ended" message), all audited.
func checkMaintenance(t *testing.T, b browser, s *stack) {
	t.Helper()
	expectRedirect(t, b.submit("/servers/r730xd/maintenance/new", "/servers/r730xd/maintenance",
		url.Values{"reason": {"PSU2 replacement"}, "duration": {"4h"}}), "/servers/r730xd/activity#maint")
	expectPage(t, b.get("/servers/r730xd"), "In maintenance</span> until")
	expectPage(t, b.get("/servers/r730xd/activity"), "PSU2 replacement — by ")
	expectPage(t, b.get("/"), `id="inm-h">In maintenance`)
	waitFor(t, "maintenance started message", func() bool {
		return s.hooks.has(notify.ClassMaintenance, "maintenance started")
	})
	if api := apiServers(t, b, s); !strings.Contains(api, `"reason":"PSU2 replacement"`) || !strings.Contains(api, `"active":true`) {
		t.Fatalf("API lacks the window: %s", api)
	}

	expectRedirect(t, b.submit("/servers/r730xd/notes/new", "/servers/r730xd/notes",
		url.Values{"body": {"PSU2 cable loose <b>x</b> https://example.com/rma"}}), "/servers/r730xd/activity#notes")
	srv := b.get("/servers/r730xd/activity")
	m := regexp.MustCompile(`name="note" value="([0-9]+)"`).FindStringSubmatch(srv.body)
	if m == nil {
		t.Fatal("no pin form")
	}
	expectRedirect(t, b.submit("/servers/r730xd/activity", "/servers/r730xd/notes/pin", url.Values{"note": {m[1]}}), "/servers/r730xd/activity#notes")
	expectPage(t, b.get("/servers/r730xd"), "<strong>Pinned note:</strong>", "PSU2 cable loose &lt;b&gt;x&lt;/b&gt;",
		`rel="noopener noreferrer"`)

	var logs page
	waitFor(t, "SEL read", func() bool {
		logs = b.get("/servers/r730xd/events")
		return strings.Contains(logs.body, "Acknowledge all")
	})
	bulk := logs.body[strings.Index(logs.body, `class="filters panel ackall"`):]
	bulk = bulk[:strings.Index(bulk, "</form>")]
	var refs []string
	for _, r := range e2eRefRE.FindAllStringSubmatch(bulk, -1) {
		refs = append(refs, html.UnescapeString(r[1]))
	}
	expectRedirect(t, b.submit("/servers/r730xd/events", "/servers/r730xd/acks",
		url.Values{"ref": refs, "comment": {"chassis opened for the swap"}, "back": {"/servers/r730xd/events"}}),
		"/servers/r730xd/events")
	expectPage(t, b.get("/servers/r730xd/events"), "Acked</span> by", "chassis opened for the swap")
	if p := b.do("GET", "/api/v1/servers/r730xd", s.token, nil); !strings.Contains(p.body, `"comment":"chassis opened for the swap"`) {
		t.Fatalf("API lacks the acks: %s", p.body)
	}

	expectRedirect(t, b.submit("/servers/r730xd/activity", "/servers/r730xd/maintenance/end", nil), "/servers/r730xd/activity#maint")
	expectPage(t, b.get("/servers/r730xd/activity"), "Not in maintenance")
	waitFor(t, "maintenance ended message", func() bool {
		return s.hooks.has(notify.ClassMaintenance, "maintenance ended")
	})
}

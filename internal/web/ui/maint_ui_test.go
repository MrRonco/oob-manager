package ui

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
	"oob-manager/internal/maint"
	"oob-manager/internal/web"
)

type maintEnv struct {
	*settingsEnv
	m *maint.Service
}

// newMaintEnv is the Settings env with a real maint.Service over the same database.
func newMaintEnv(t *testing.T) *maintEnv {
	t.Helper()
	e := newSettingsEnv(t)
	m, err := maint.New(context.Background(), maint.Config{DB: e.db,
		Audit: audit.NewLogger(e.db.Audit(), nil, e.clock.Now, quiet()), Logger: quiet(), Now: e.clock.Now})
	must(t, err)
	e.deps.Maintenance = m
	app, err := New(e.deps)
	must(t, err)
	e.handler, err = web.NewHandler(app, web.Options{Logger: quiet()})
	must(t, err)
	return &maintEnv{settingsEnv: e, m: m}
}

func (e *maintEnv) userClient(t *testing.T, name string, role authz.Role, ip string) *client {
	t.Helper()
	link, err := e.svc.CreateUser(context.Background(), actorFor(t, e.settingsEnv, "morgan"), name, role)
	must(t, err)
	c := e.client(ip)
	c.login(name, e.enrolViaLink(link.Token, testPassword))
	return c
}

func TestMaintenanceModeUI(t *testing.T) {
	e := newMaintEnv(t)
	op := e.userClient(t, "oscar", authz.RoleOperator, "192.0.2.30")
	viewer := e.userClient(t, "vera", authz.RoleViewer, "192.0.2.31")
	result(viewer.get("/servers/r730xd/activity")).contains(t, "Not in maintenance").lacks(t, "Start maintenance")
	result(op.get("/")).contains(t, "Power supply PS2 reports Critical").lacks(t, "In maintenance")

	start := url.Values{"reason": {"PSU2 <b>swap</b>"}, "duration": {"4h"}}
	result(op.submit("/servers/r730xd/maintenance/new", "/servers/r730xd/maintenance", start)).
		status(t, http.StatusSeeOther).location(t, "/servers/r730xd/activity#maint")
	if _, ok := e.m.Active("r730xd"); !ok {
		t.Fatal("not in maintenance")
	}
	page := result(viewer.get("/servers/r730xd/activity")).status(t, http.StatusOK)
	page.contains(t, "In maintenance</span> until <time", "PSU2 &lt;b&gt;swap&lt;/b&gt; — by oscar", `class="panel p-maint"`).
		lacks(t, "<b>swap</b>", "End maintenance now")
	result(op.get("/servers/r730xd/activity")).contains(t, "End maintenance now")

	// Overview: shown in its own group, not counted in the verdict or Needs attention.
	ov := result(viewer.get("/")).status(t, http.StatusOK)
	ov.contains(t, `id="inm-h">In maintenance`, "Power supply PS2 reports Critical", `<span>1 in maintenance</span>`,
		"2 stale · 1 in maintenance", `class="smaint"`)
	attn := ov.rec.Body.String()
	attn = attn[strings.Index(attn, `id="verdict"`):strings.Index(attn, `id="inm-h"`)]
	if strings.Contains(attn, "PS2") {
		t.Fatal("a server in maintenance is still in Needs attention")
	}

	// Refusals.
	result(op.submit("/servers/r730xd/activity", "/servers/r730xd/maintenance/end", nil)).status(t, http.StatusSeeOther)
	tok := e.csrfToken(op)
	result(op.do(http.MethodPost, "/servers/r730xd/maintenance", url.Values{csrfField: {tok}, "duration": {"1h"}})).
		status(t, http.StatusUnprocessableEntity).contains(t, "A reason is required.")
	result(op.do(http.MethodPost, "/servers/r730xd/maintenance", url.Values{csrfField: {tok}, "reason": {"x"}, "duration": {"9d"}})).
		status(t, http.StatusUnprocessableEntity).contains(t, "Choose how long")
	result(op.do(http.MethodPost, "/servers/nope/maintenance", url.Values{csrfField: {tok}, "reason": {"x"}, "duration": {"1h"}})).
		status(t, http.StatusNotFound)
	result(op.do(http.MethodPost, "/servers/r730xd/maintenance/end", url.Values{csrfField: {tok}})).status(t, http.StatusNotFound)
	result(viewer.do(http.MethodPost, "/servers/r730xd/maintenance", url.Values{csrfField: {e.csrfToken(viewer)},
		"reason": {"x"}, "duration": {"1h"}})).status(t, http.StatusForbidden)
	result(op.do(http.MethodPost, "/servers/r730xd/maintenance", url.Values{"reason": {"x"}, "duration": {"1h"}})).
		status(t, http.StatusForbidden)

	// Custom end in the user's zone, and a scheduled window.
	custom := url.Values{csrfField: {tok}, "reason": {"firmware"}, "duration": {"custom"}, "ends_at": {"2026-10-21T11:30"}}
	result(op.do(http.MethodPost, "/servers/r240/maintenance", custom)).status(t, http.StatusSeeOther)
	if w, ok := e.m.Active("r240"); !ok || !w.EndsAt.Equal(time.Date(2026, 10, 21, 11, 30, 0, 0, time.UTC)) {
		t.Fatalf("custom window %+v", w)
	}
	result(op.do(http.MethodPost, "/servers/r240/maintenance", custom)).status(t, http.StatusConflict)
	for _, bad := range []url.Values{
		{"reason": {"x"}, "duration": {"custom"}},
		{"reason": {"x"}, "duration": {"custom"}, "ends_at": {"2026-10-21T08:00"}},
		{"reason": {"x"}, "duration": {"1h"}, "starts_at": {"tomorrow"}},
	} {
		bad.Set(csrfField, tok)
		result(op.do(http.MethodPost, "/servers/spare/maintenance", bad)).status(t, http.StatusUnprocessableEntity)
	}
	later := url.Values{csrfField: {tok}, "reason": {"rack move"}, "duration": {"until"}, "starts_at": {"2026-10-22T09:00"}}
	result(op.do(http.MethodPost, "/servers/spare/maintenance", later)).status(t, http.StatusSeeOther)
	result(op.get("/servers/spare/activity")).contains(t, "Maintenance scheduled</span> from", "until ended", "Cancel scheduled maintenance")
	result(op.get("/")).lacks(t, "Spare box</a> <span class=\"badge b-maint\"")
	if _, ok := e.findAudit(maint.ActionStart, audit.ResultOK); !ok {
		t.Fatal("start not audited")
	}
	if !e.auditContains(`"reason":"ended"`) {
		t.Fatal("end not audited")
	}
	result(e.adminClient().get("/settings/audit")).contains(t, "started or scheduled maintenance of", "ended maintenance of")
}

func TestPillAllInMaintenance(t *testing.T) {
	c := fleetCounts{Total: 2, Maintenance: 2}
	if p := pillOf(c); p.Class != "gp-maint" || p.Text != "All 2 in maintenance" {
		t.Fatalf("pill %+v", p)
	}
	if p := pillOf(fleetCounts{Total: 3, OK: 2, Maintenance: 1}); p.Text != "2 OK · 1 in maintenance" {
		t.Fatalf("pill %+v", p)
	}
	if p := pillOf(fleetCounts{Total: 3, Critical: 1, OK: 1, Maintenance: 1}); p.Class != "gp-crit" ||
		p.Text != "1 critical · 1 in maintenance" {
		t.Fatalf("pill %+v", p)
	}
}

func TestNotesUI(t *testing.T) {
	e := newMaintEnv(t)
	op := e.userClient(t, "oscar", authz.RoleOperator, "192.0.2.30")
	other := e.userClient(t, "olga", authz.RoleOperator, "192.0.2.32")
	viewer := e.userClient(t, "vera", authz.RoleViewer, "192.0.2.31")
	admin := e.adminClient()
	xss := "PSU2 cable loose <script>alert(1)</script>\nsee https://example.com/rma?a=1&b=2. and javascript:alert(1)"
	result(op.submit("/servers/r730xd/notes/new", "/servers/r730xd/notes", url.Values{"body": {xss}})).
		status(t, http.StatusSeeOther).location(t, "/servers/r730xd/activity#notes")
	notes := e.m.Notes("r730xd")
	if len(notes) != 1 {
		t.Fatalf("notes %+v", notes)
	}
	id := notes[0].ID
	page := result(viewer.get("/servers/r730xd/activity")).status(t, http.StatusOK)
	page.contains(t, "&lt;script&gt;alert(1)&lt;/script&gt;\nsee ",
		`<a href="https://example.com/rma?a=1&amp;b=2" rel="noopener noreferrer" target="_blank">https://example.com/rma?a=1&amp;b=2</a>. and javascript:alert(1)`).
		lacks(t, "<script>alert(1)</script>", `href="javascript`, "Add a note", "Pin to top")

	nid := "/servers/r730xd/notes/" + itoa(id)
	result(op.submit("/servers/r730xd/activity", "/servers/r730xd/notes/pin", url.Values{"note": {itoa(id)}})).status(t, http.StatusSeeOther)
	result(viewer.get("/servers/r730xd")).contains(t, "<strong>Pinned note:</strong>")
	result(viewer.get("/servers/r730xd/activity")).contains(t, `class="pin"`)
	result(other.get("/servers/r730xd/activity")).contains(t, "Unpin").lacks(t, `action="`+nid+`"`, `action="`+nid+`/delete"`, `href="`+nid+`/edit"`)
	tok := e.csrfToken(other)
	result(other.do(http.MethodPost, nid, url.Values{csrfField: {tok}, "body": {"mine"}})).status(t, http.StatusForbidden)
	result(other.do(http.MethodPost, nid+"/delete", url.Values{csrfField: {tok}})).status(t, http.StatusForbidden)
	result(viewer.do(http.MethodPost, "/servers/r730xd/notes", url.Values{csrfField: {e.csrfToken(viewer)}, "body": {"x"}})).
		status(t, http.StatusForbidden)

	e.clock.Advance(time.Minute)
	result(op.submit(nid+"/edit", nid, url.Values{"body": {"PSU2 cable reseated"}})).
		status(t, http.StatusSeeOther).location(t, "/servers/r730xd#note-"+itoa(id))
	result(viewer.get("/servers/r730xd/activity")).contains(t, "PSU2 cable reseated", " · edited ")
	optok := e.csrfToken(op)
	result(op.do(http.MethodPost, "/servers/r730xd/notes", url.Values{csrfField: {optok}, "body": {" "}})).
		status(t, http.StatusUnprocessableEntity).contains(t, "The note is empty.")
	result(op.do(http.MethodPost, "/servers/r730xd/notes/pin", url.Values{csrfField: {optok}, "note": {"x"}})).status(t, http.StatusBadRequest)
	result(op.do(http.MethodPost, "/servers/r730xd/notes/abc", url.Values{csrfField: {optok}, "body": {"x"}})).status(t, http.StatusNotFound)
	result(op.do(http.MethodPost, "/servers/r730xd/notes/pin", url.Values{csrfField: {optok}, "note": {"0"}})).status(t, http.StatusSeeOther)
	result(admin.get("/servers/r730xd/activity")).contains(t, `action="`+nid+`/delete"`)
	result(admin.submit("/servers/r730xd/activity", nid+"/delete", nil)).status(t, http.StatusSeeOther)
	result(viewer.get("/servers/r730xd/activity")).contains(t, "No notes yet.")
	result(op.do(http.MethodPost, nid+"/delete", url.Values{csrfField: {optok}})).status(t, http.StatusNotFound)
	if e.auditContains("PSU2") {
		t.Fatal("note text in the audit log")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func ackFleet(e *maintEnv) time.Time {
	now := e.clock.Now()
	e.fleet.logs["r730xd/sel"] = bmc.NewEventLog("", []bmc.Event{
		{ID: "8", Created: now.Add(-2 * time.Hour), Message: "Power supply 2 input lost.", MessageID: "PSU0003", Severity: bmc.SeverityWarning},
		{ID: "7", Created: now.Add(-3 * time.Hour), Message: "Clock synchronized.", Severity: bmc.SeverityOK},
		{ID: "6", Created: now.Add(-4 * time.Hour), Message: "The chassis is open.", Severity: bmc.SeverityCritical},
	}, true)
	return now
}

func TestAcknowledgeUI(t *testing.T) {
	e := newMaintEnv(t)
	base := ackFleet(e)
	op := e.userClient(t, "oscar", authz.RoleOperator, "192.0.2.30")
	viewer := e.userClient(t, "vera", authz.RoleViewer, "192.0.2.31")
	result(viewer.get("/servers/r730xd/events")).lacks(t, "Acknowledge<span class=\"sr-only\"> entry")
	result(op.get("/")).contains(t, "The chassis is open.", "Power supply 2 input lost.")
	logs := result(op.get("/servers/r730xd/events")).status(t, http.StatusOK)
	logs.contains(t, "Acknowledge<span class=\"sr-only\"> entry", "Acknowledge all 2 shown", `value="sel|`)
	ref := "sel|" + itoa(base.Add(-4*time.Hour).UnixMilli()) + "|6"
	tok := e.csrfToken(op)
	rec := op.do(http.MethodPost, "/servers/r730xd/acks", url.Values{csrfField: {tok}, "ref": {ref},
		"comment": {"lid open for the PSU swap"}, "back": {"/servers/r730xd/events?log=sel"}})
	result(rec).status(t, http.StatusSeeOther).location(t, "/servers/r730xd/events?log=sel")
	result(viewer.get("/events?server=r730xd")).contains(t, "Acked</span> by oscar at <time", ": lid open for the PSU swap")
	ov := result(viewer.get("/")).rec.Body.String()
	attn := ov[strings.Index(ov, `id="verdict"`):strings.Index(ov, `id="fleet-h"`)]
	if strings.Contains(attn, "The chassis is open.") || !strings.Contains(attn, "Power supply 2 input lost.") {
		t.Fatalf("attention after ack:\n%s", attn)
	}
	// A new entry of the same kind is not acknowledged.
	now := base
	e.fleet.logs["r730xd/sel"] = bmc.NewEventLog("", []bmc.Event{
		{ID: "9", Created: now.Add(-time.Minute), Message: "The chassis is open.", Severity: bmc.SeverityCritical},
		{ID: "6", Created: now.Add(-4 * time.Hour), Message: "The chassis is open.", Severity: bmc.SeverityCritical},
	}, true)
	ov = result(viewer.get("/")).rec.Body.String()
	if strings.Count(ov[strings.Index(ov, `id="verdict"`):strings.Index(ov, `id="fleet-h"`)], "The chassis is open.") != 1 {
		t.Fatal("new entry of the same kind")
	}

	// Refusals: unknown or info entries, bad refs, viewers.
	for _, bad := range []string{"sel|1|6", "sel|" + itoa(now.Add(-3*time.Hour).UnixMilli()) + "|7", "audit|0|1", "garbage"} {
		result(op.do(http.MethodPost, "/servers/r730xd/acks", url.Values{csrfField: {tok}, "ref": {bad}})).status(t, http.StatusBadRequest)
	}
	result(op.do(http.MethodPost, "/servers/r730xd/acks", url.Values{csrfField: {tok}})).status(t, http.StatusBadRequest)
	result(op.do(http.MethodPost, "/servers/r730xd/acks", url.Values{csrfField: {tok}, "ref": {ref}, "comment": {"a\x01b"}})).
		status(t, http.StatusUnprocessableEntity)
	result(viewer.do(http.MethodPost, "/servers/r730xd/acks", url.Values{csrfField: {e.csrfToken(viewer)}, "ref": {ref}})).
		status(t, http.StatusForbidden)

	// Un-acknowledge, then acknowledge everything shown at once (back defaults to the logs).
	result(op.do(http.MethodPost, "/servers/r730xd/acks/remove", url.Values{csrfField: {tok}, "ref": {ref}, "back": {"https://evil.test/"}})).
		status(t, http.StatusSeeOther).location(t, "/servers/r730xd/events")
	result(op.do(http.MethodPost, "/servers/r730xd/acks/remove", url.Values{csrfField: {tok}, "ref": {ref}})).status(t, http.StatusNotFound)
	result(op.do(http.MethodPost, "/servers/r730xd/acks/remove", url.Values{csrfField: {tok}, "ref": {"x"}})).status(t, http.StatusBadRequest)
	page := op.get("/events?server=r730xd").Body.String()
	if !strings.Contains(page, "Acknowledge all 2 shown") {
		t.Fatalf("no bulk form:\n%s", page)
	}
	bulk := page[strings.Index(page, `class="filters panel ackall"`):]
	bulk = bulk[:strings.Index(bulk, "</form>")]
	var refs []string
	for _, m := range regexp.MustCompile(`name="ref" value="([^"]+)"`).FindAllStringSubmatch(bulk, -1) {
		refs = append(refs, html.UnescapeString(m[1]))
	}
	all := result(op.submit("/events?server=r730xd", "/servers/r730xd/acks", url.Values{"comment": {"bulk"}, "ref": refs,
		"back": {"/events?server=r730xd"}}))
	all.status(t, http.StatusSeeOther).location(t, "/events?server=r730xd")
	if acks := e.m.Acks("r730xd"); len(acks) != 2 {
		t.Fatalf("bulk acks %+v", acks)
	}
	ov = result(viewer.get("/")).rec.Body.String()
	if strings.Contains(ov[strings.Index(ov, `id="verdict"`):strings.Index(ov, `id="fleet-h"`)], "The chassis is open.") {
		t.Fatal("acknowledged entries still need attention")
	}
	if _, ok := e.findAudit(maint.ActionUnack, audit.ResultOK); !ok {
		t.Fatal("unack not audited")
	}
}

func TestMaintenanceHiddenWithoutService(t *testing.T) {
	e := newSettingsEnv(t)
	c := e.adminClient()
	result(c.get("/servers/r730xd/activity")).lacks(t, `id="maint-h"`, `id="notes-h"`)
	result(c.get("/servers/r730xd/events")).lacks(t, "Acknowledge")
	result(c.do(http.MethodPost, "/servers/r730xd/notes", url.Values{csrfField: {e.csrfToken(c)}, "body": {"x"}})).
		status(t, http.StatusNotFound)
}

func TestLinkify(t *testing.T) {
	segs := linkify("a http://x.test/p) b https:// c ftp://no http://ok.test/q?x=1.")
	var links []string
	for _, s := range segs {
		if s.Href != "" {
			links = append(links, s.Href)
		}
	}
	if strings.Join(links, " ") != "http://x.test/p http://ok.test/q?x=1" {
		t.Fatalf("links %q", links)
	}
	var text strings.Builder
	for _, s := range segs {
		text.WriteString(s.Text)
	}
	if text.String() != "a http://x.test/p) b https:// c ftp://no http://ok.test/q?x=1." {
		t.Fatalf("text not preserved: %q", text.String())
	}
}

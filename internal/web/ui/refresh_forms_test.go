package ui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"oob-manager/internal/authz"
)

// Audit R2-02: auto-refresh discarded everything typed on the server page. The
// maintenance and note forms now live on their own pages, so a refreshed page never
// carries typed input, and the refresh itself is a no-script fallback plus a script
// that pauses while a field is focused or dirty.

// typedInputs are the controls a refresh would wipe.
var typedInputs = []string{"<textarea", `type="text"`, `type="search"`, `type="datetime-local"`, `type="password"`, `type="number"`}

func TestRefreshedPagesCarryNoTypedInput(t *testing.T) {
	t.Parallel()
	e := newMaintEnv(t)
	op := e.userClient(t, "oscar", authz.RoleOperator, "192.0.2.30")
	result(op.submit("/", "/prefs/refresh", url.Values{"refresh": {"on"}, "next": {"/"}})).status(t, http.StatusSeeOther)
	for _, path := range []string{"/", "/servers", "/servers/r730xd"} {
		r := result(op.get(path)).status(t, http.StatusOK)
		r.contains(t, `<noscript><meta http-equiv="refresh" content="60"></noscript>`, `<meta name="oob-refresh" content="60">`)
		r.lacks(t, typedInputs...)
	}
	result(op.get("/servers/r730xd/activity")).contains(t, `href="/servers/r730xd/maintenance/new"`, `href="/servers/r730xd/notes/new"`)
	// Pages with forms never refresh, whatever the preference says.
	for _, path := range []string{"/servers/r730xd/maintenance/new", "/servers/r730xd/notes/new", "/servers/r730xd/fan", "/events"} {
		result(op.get(path)).status(t, http.StatusOK).lacks(t, `http-equiv="refresh"`, `name="oob-refresh"`)
	}
}

func TestMaintenanceFormPage(t *testing.T) {
	t.Parallel()
	e := newMaintEnv(t)
	op := e.userClient(t, "oscar", authz.RoleOperator, "192.0.2.30")
	viewer := e.userClient(t, "vera", authz.RoleViewer, "192.0.2.31")
	result(viewer.get("/servers/r730xd/maintenance/new")).status(t, http.StatusForbidden)
	result(viewer.get("/servers/r730xd/activity")).lacks(t, "maintenance/new")
	result(op.get("/servers/nope/maintenance/new")).status(t, http.StatusNotFound)
	page := result(op.get("/servers/r730xd/maintenance/new")).status(t, http.StatusOK)
	page.contains(t, "<h1>Storage node R730XD: start maintenance</h1>", `action="/servers/r730xd/maintenance"`, `id="maint-reason"`,
		`name="duration"`, `href="/servers/r730xd/activity#maint">Cancel</a>`)

	// A validation error re-renders the page with what was typed, never a bare error page.
	tok := e.csrfToken(op)
	bad := result(op.do(http.MethodPost, "/servers/r730xd/maintenance", url.Values{csrfField: {tok}, "duration": {"custom"},
		"reason": {"PSU2 <swap>"}, "ends_at": {"2026-10-21T08:00"}}))
	bad.status(t, http.StatusUnprocessableEntity).contains(t, "The end must be after the start.", `value="PSU2 &lt;swap&gt;"`,
		`value="2026-10-21T08:00"`, `<option value="custom" selected>`, `aria-invalid="true"`).lacks(t, "<swap>")

	result(op.submit("/servers/r730xd/maintenance/new", "/servers/r730xd/maintenance",
		url.Values{"reason": {"PSU2 swap"}, "duration": {"1h"}})).status(t, http.StatusSeeOther).location(t, "/servers/r730xd/activity#maint")
	// With a window in place the page offers no second form, only the way back.
	result(op.get("/servers/r730xd/maintenance/new")).status(t, http.StatusOK).
		contains(t, "already has a maintenance window", `href="/servers/r730xd/activity#maint"`).lacks(t, `id="maint-reason"`)
	result(op.get("/servers/r730xd/activity")).contains(t, "End maintenance now").lacks(t, "maintenance/new")
}

func TestNoteFormPages(t *testing.T) {
	t.Parallel()
	e := newMaintEnv(t)
	op := e.userClient(t, "oscar", authz.RoleOperator, "192.0.2.30")
	other := e.userClient(t, "olga", authz.RoleOperator, "192.0.2.32")
	viewer := e.userClient(t, "vera", authz.RoleViewer, "192.0.2.31")
	result(viewer.get("/servers/r730xd/notes/new")).status(t, http.StatusForbidden)
	add := result(op.get("/servers/r730xd/notes/new")).status(t, http.StatusOK)
	add.contains(t, "<h1>Storage node R730XD: add a note</h1>", `action="/servers/r730xd/notes"`, `id="note-body"`,
		`href="/servers/r730xd/activity#notes">Cancel</a>`)
	tok := e.csrfToken(op)
	result(op.do(http.MethodPost, "/servers/r730xd/notes", url.Values{csrfField: {tok}, "body": {" "}})).
		status(t, http.StatusUnprocessableEntity).contains(t, "The note is empty.", `id="note-body"`)
	result(op.submit("/servers/r730xd/notes/new", "/servers/r730xd/notes", url.Values{"body": {"PSU2 cable <loose>"}})).
		status(t, http.StatusSeeOther).location(t, "/servers/r730xd/activity#notes")
	notes := e.m.Notes("r730xd")
	if len(notes) != 1 {
		t.Fatalf("notes %+v", notes)
	}
	edit := "/servers/r730xd/notes/" + itoa(notes[0].ID) + "/edit"
	result(op.get("/servers/r730xd/activity")).contains(t, `href="`+edit+`"`)
	result(other.get("/servers/r730xd/activity")).lacks(t, `href="`+edit+`"`)
	result(other.get(edit)).status(t, http.StatusForbidden)
	result(viewer.get(edit)).status(t, http.StatusForbidden)
	result(op.get("/servers/r730xd/notes/999/edit")).status(t, http.StatusNotFound)
	result(op.get("/servers/r730xd/notes/abc/edit")).status(t, http.StatusNotFound)
	page := result(op.get(edit)).status(t, http.StatusOK)
	page.contains(t, "<h1>Storage node R730XD: edit note</h1>", `action="/servers/r730xd/notes/`+itoa(notes[0].ID)+`"`,
		">PSU2 cable &lt;loose&gt;</textarea>", "Save note").lacks(t, "<loose>")
	result(op.submit(edit, "/servers/r730xd/notes/"+itoa(notes[0].ID), url.Values{"body": {"PSU2 cable reseated"}})).
		status(t, http.StatusSeeOther)
	if got := e.m.Notes("r730xd")[0].Body; got != "PSU2 cable reseated" {
		t.Fatalf("edited body %q", got)
	}
	if !strings.Contains(result(op.get(edit)).rec.Body.String(), ">PSU2 cable reseated</textarea>") {
		t.Fatal("the edit page does not show the current text")
	}
}

// TestFormPagesNeverMetaRefresh (review R8): no page that carries typed input is
// refreshed by the no-script meta refresh. The Security tab (accept comments) never
// refreshes; the server edit page refreshes during a connection test only through the
// script, which pauses while a field is focused or dirty, and says how to see the result
// without scripts.
func TestFormPagesNeverMetaRefresh(t *testing.T) {
	t.Parallel()
	sec := newSecEnv(t)
	adm := sec.adminClient()
	result(adm.submit("/", "/prefs/refresh", url.Values{"refresh": {"on"}, "next": {"/"}})).status(t, http.StatusSeeOther)
	result(adm.get("/servers/r730xd/security")).status(t, http.StatusOK).contains(t, `name="comment" type="text"`).
		lacks(t, `http-equiv="refresh"`, `name="oob-refresh"`)

	e := newServersEnv(t, "")
	c := e.adminClient()
	e.fetchAndConfirm(t, c, "edge1", "192.0.2.12").status(t, http.StatusSeeOther)
	e.prober.mu.Lock()
	e.prober.last["edge1"] = ServerTest{Running: true}
	e.prober.mu.Unlock()
	page := result(c.get("/settings/servers/edge1")).status(t, http.StatusOK)
	page.contains(t, `<meta name="oob-refresh" content="5">`, `type="text"`, "Reload this page to see the result.").
		lacks(t, `http-equiv="refresh"`)
}

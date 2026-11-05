package ui

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

// TestKeptFormLabels (review R7): when a kept form will be replayed, the step-up page
// names that change (accept or remove a risk, maintenance, notes, acknowledgements), not
// "Make changes". Only a configured server's name is interpolated.
func TestKeptFormLabels(t *testing.T) {
	t.Parallel()
	name := func(id string) string {
		if id == "edge" {
			return "Edge router"
		}
		return ""
	}
	for path, want := range map[string]string{
		"/servers/edge/security/accept":        "Accept a security risk · Edge router",
		"/servers/edge/security/accept/remove": "Remove an accepted risk · Edge router",
		"/servers/edge/maintenance":            "Start maintenance · Edge router",
		"/servers/edge/maintenance/end":        "End maintenance · Edge router",
		"/servers/edge/notes":                  "Add a note · Edge router",
		"/servers/edge/notes/pin":              "Pin a note · Edge router",
		"/servers/edge/notes/12":               "Change a note · Edge router",
		"/servers/edge/notes/12/delete":        "Delete a note · Edge router",
		"/servers/edge/acks":                   "Acknowledge events · Edge router",
		"/servers/edge/acks/remove":            "Remove an acknowledgement · Edge router",
		"/servers/nope/security/accept":        "",
		"/servers/edge/security/rerun":         "",
		"/servers/edge/power/on":               "",
		"/settings/general":                    "",
		"/servers/edge/notes/n1":               "",
		"/servers/../security/accept":          "",
	} {
		if got := keptFormLabel(path, name); got != want {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
}

// The Security tab's step-up page says what the kept form does; without a kept form it
// names the tab's changes.
func TestSecurityStepUpNamesTheChange(t *testing.T) {
	t.Parallel()
	e := newSecEnv(t)
	adm := e.adminClient()
	const tab = "/servers/r730xd/security"
	server := e.fleet.servers[0].Name
	e.clock.Advance(6 * time.Minute)
	loc, _ := resumeFrom(t, result(adm.submit(tab, tab+"/accept",
		url.Values{"check": {"svc.telnet"}, "comment": {"x"}, "seen": {seenOf(t, "svc.telnet")}})), tab)
	result(adm.get(loc)).status(t, http.StatusOK).contains(t, "<strong>Accept a security risk · "+server+"</strong>").lacks(t, "Make changes")
	loc, _ = resumeFrom(t, result(adm.submit(tab, tab+"/accept/remove", url.Values{"check": {"svc.ipmi"}})), tab)
	result(adm.get(loc)).contains(t, "<strong>Remove an accepted risk · "+server+"</strong>")
	result(adm.get("/stepup?next="+url.QueryEscape(tab))).contains(t, "<strong>Accept or remove security risks · "+server+"</strong>")
}

package ui

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"oob-manager/internal/authz"
	"oob-manager/internal/bmcsec"
)

// TestAcceptNeedsAFreshStepUp: accepting a risk (and taking it back) is an admin change
// that silences a finding, so like every admin change it needs a step-up inside the
// window; a stale one is sent to the step-up page (the form kept) and audited. A re-run
// only reads.
func TestAcceptNeedsAFreshStepUp(t *testing.T) {
	t.Parallel()
	e := newSecEnv(t)
	adm := e.adminClient()
	const tab = "/servers/r730xd/security"
	e.clock.Advance(6 * time.Minute) // past the 5-minute step-up window, inside the session's idle timeout
	rec := adm.submit(tab, tab+"/accept", url.Values{"check": {"svc.telnet"}, "comment": {"x"}, "seen": {seenOf(t, "svc.telnet")}})
	resumeFrom(t, result(rec), tab)
	rec = adm.submit(tab, tab+"/accept/remove", url.Values{"check": {"svc.ipmi"}})
	resumeFrom(t, result(rec), tab)
	if len(e.sec.accepts) != 0 || len(e.sec.unaccepts) != 0 {
		t.Fatalf("changed without a fresh step-up: %v %v", e.sec.accepts, e.sec.unaccepts)
	}
	if rec, ok := e.findAudit(string(authz.SecurityAccept), "denied"); !ok || rec.ErrorClass != "stepup_required" || rec.ServerID != "r730xd" {
		t.Fatalf("refusal not audited: %+v %v", rec, ok)
	}
	result(adm.submit(tab, tab+"/rerun", nil)).status(t, http.StatusSeeOther).location(t, tab+"?done=rerun")
}

// stepUpAndResume confirms a fresh code on the step-up page of a refused change; the kept
// form is replayed and its response returned.
func (e *secEnv) stepUpAndResume(c *client, loc, next, id string) *httpResult {
	return result(c.submit(loc, "/stepup", url.Values{"code": {e.code(e.secret)}, "next": {next}, "resume": {id}}))
}

// TestSecurityChangesResumeAfterTheStepUp (R2-03 on the Security tab): an accept or a
// removal posted after the step-up window lapsed is kept across the step-up and replayed
// once, with the comment and the "seen" value exactly as the form carried them.
func TestSecurityChangesResumeAfterTheStepUp(t *testing.T) {
	t.Parallel()
	e := newSecEnv(t)
	adm := e.adminClient()
	const tab = "/servers/r730xd/security"
	seen := seenOf(t, "svc.telnet")

	e.clock.Advance(6 * time.Minute)
	loc, id := resumeFrom(t, result(adm.submit(tab, tab+"/accept",
		url.Values{"check": {"svc.telnet"}, "comment": {"isolated lab network"}, "seen": {seen}})), tab)
	result(adm.get(loc)).contains(t, "Your form is kept", `name="resume" value="`+id+`"`)
	e.stepUpAndResume(adm, loc, tab, id).status(t, http.StatusSeeOther).location(t, tab+"?done=accepted#chk-svc-telnet")
	if len(e.sec.accepts) != 1 || e.sec.accepts[0] != "morgan/r730xd/svc.telnet/isolated lab network" || e.sec.seen[0] != seen {
		t.Fatalf("accept not replayed as posted: %v %v", e.sec.accepts, e.sec.seen)
	}

	e.clock.Advance(6 * time.Minute)
	loc, id = resumeFrom(t, result(adm.submit(tab, tab+"/accept/remove", url.Values{"check": {"svc.ipmi"}})), tab)
	e.stepUpAndResume(adm, loc, tab, id).status(t, http.StatusSeeOther).location(t, tab+"?done=unaccepted#chk-svc-ipmi")
	if len(e.sec.unaccepts) != 1 || e.sec.unaccepts[0] != "morgan/r730xd/svc.ipmi" {
		t.Fatalf("removal not replayed: %v", e.sec.unaccepts)
	}
}

// TestResumedAcceptOfAChangedFinding: when the finding changed between the stash and the
// replay, the replay gets the normal 409 "changed" notice and nothing is accepted.
func TestResumedAcceptOfAChangedFinding(t *testing.T) {
	t.Parallel()
	e := newSecEnv(t)
	adm := e.adminClient()
	const tab = "/servers/r730xd/security"
	seen := seenOf(t, "svc.telnet")
	e.clock.Advance(6 * time.Minute)
	loc, id := resumeFrom(t, result(adm.submit(tab, tab+"/accept",
		url.Values{"check": {"svc.telnet"}, "comment": {"x"}, "seen": {seen}})), tab)
	e.sec.acceptErr = bmcsec.ErrChanged // the next run changed the finding meanwhile
	e.stepUpAndResume(adm, loc, tab, id).status(t, http.StatusConflict).
		contains(t, "This finding changed since the page was loaded; review it again.", `role="alert"`, `id="chk-svc-telnet"`)
	if len(e.sec.accepts) != 0 || len(e.sec.seen) != 1 || e.sec.seen[0] != seen {
		t.Fatalf("accepted %v, seen replayed %v (want exactly %q)", e.sec.accepts, e.sec.seen, seen)
	}
}

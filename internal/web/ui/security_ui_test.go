package ui

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
	"oob-manager/internal/bmcsec"
	"oob-manager/internal/fleet"
)

// fakeSecurity is the security check service as the UI sees it.
type fakeSecurity struct {
	mu        sync.Mutex
	reports   map[string]bmcsec.Report
	status    map[string]bmcsec.RunStatus
	reruns    []string
	accepts   []string
	seen      []string // the "seen" value of each accept
	unaccepts []string
	rerunErr  error
	acceptErr error
}

func (f *fakeSecurity) Available() bool { return true }

func (f *fakeSecurity) Report(id string) (bmcsec.Report, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.reports[id]
	return r, ok
}

func (f *fakeSecurity) Status(id string) bmcsec.RunStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status[id]
}

func (f *fakeSecurity) Accept(_ context.Context, a admin.Actor, id, check, comment, seen string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, seen) // what the form carried, also when the accept is refused
	if f.acceptErr != nil {
		return f.acceptErr
	}
	if _, err := bmcsec.CleanComment(comment); err != nil {
		return err
	}
	f.accepts = append(f.accepts, a.Username+"/"+id+"/"+check+"/"+comment)
	return nil
}

func (f *fakeSecurity) Unaccept(_ context.Context, a admin.Actor, id, check string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if check == "svc.snmp" {
		return bmcsec.ErrNotFound
	}
	f.unaccepts = append(f.unaccepts, a.Username+"/"+id+"/"+check)
	return nil
}

func (f *fakeSecurity) Rerun(_ context.Context, a admin.Actor, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rerunErr != nil {
		return f.rerunErr
	}
	f.reruns = append(f.reruns, a.Username+"/"+id)
	return nil
}

var secAt = time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)

// testReport has a failing Telnet, a warning for IPMI (accepted), a warning for SNMP,
// a check that cannot be read and a hostile string in the evidence.
func testReport() bmcsec.Report {
	ok := bmc.SectionOf(nil)
	p := bmc.Posture{Started: secAt, Duration: 12 * time.Second, Redfish: bmc.RedfishPosture{
		Protocols: bmc.ProtocolFacts{Read: ok, IPMI: bmc.FactOf(true, "np"), Telnet: bmc.FactOf(true, "np"),
			SNMP: bmc.FactOf(true, "np"), SNMPLegacy: bmc.FactOf(true, "np"), SSH: bmc.FactOf(false, "np")},
		Accounts: bmc.AccountFacts{Read: bmc.Section{State: bmc.ReadForbidden}},
		Firmware: bmc.FirmwareFacts{Read: ok, BMCVersion: "2.86<script>alert(1)</script>"},
	}}
	r := bmcsec.Evaluate("r730xd", p, bmcsec.Inputs{Kind: "idrac8"}, secAt)
	for i, f := range r.Findings {
		if f.Check.ID == "svc.ipmi" {
			r.Findings[i].Accepted = &bmcsec.Acceptance{CheckID: "svc.ipmi", Result: f.Result, Subject: f.Subject,
				Comment: "the <UPS> card polls it", By: "morgan", At: secAt}
		}
	}
	return r
}

type secEnv struct {
	*settingsEnv
	sec *fakeSecurity
}

func newSecEnv(t *testing.T) *secEnv {
	t.Helper()
	sec := &fakeSecurity{reports: map[string]bmcsec.Report{"r730xd": testReport()},
		status: map[string]bmcsec.RunStatus{
			"r730xd": {Enabled: true, HasReport: true, AsOf: secAt, Took: 12 * time.Second, Every: 6 * time.Hour,
				NextAround: secAt.Add(6 * time.Hour)},
			"r240":  {Enabled: true, Running: true},
			"spare": {Enabled: false},
		}}
	e := newSettingsEnv(t, func(d *Deps) { d.Security = sec })
	return &secEnv{settingsEnv: e, sec: sec}
}

func (e *secEnv) userClient(t *testing.T, name string, role authz.Role, ip string) *client {
	t.Helper()
	link, err := e.svc.CreateUser(context.Background(), actorFor(t, e.settingsEnv, "morgan"), name, role)
	must(t, err)
	c := e.client(ip)
	c.login(name, e.enrolViaLink(link.Token, testPassword))
	return c
}

func TestSecurityTabViewerSeesTheSummaryOnly(t *testing.T) {
	t.Parallel()
	e := newSecEnv(t)
	viewer := e.userClient(t, "vera", authz.RoleViewer, "192.0.2.31")
	page := result(viewer.get("/servers/r730xd/security")).status(t, http.StatusOK)
	page.contains(t, "<h1>Storage node R730XD: security", `href="/servers/r730xd/security" aria-current="page">`, "BMC security checks",
		"<dt>Fail</dt><dd>1</dd>", "<dt>Accepted risk</dt><dd>1</dd>", "need the operator role",
		`datetime="2026-10-21T08:00:00Z"`, "Read-only:").
		contains(t, "Re-running the checks needs the admin role.").
		lacks(t, "Telnet is on", "Why it matters", "Accept as a risk", `action="/servers/r730xd/security/rerun"`,
			"Re-run checks", `id="rerun-why"`) // status for a viewer, not a dead button (R2-11)
	if strings.Contains(page.rec.Body.String(), "<script>alert") {
		t.Fatal("unescaped BMC text")
	}
}

func TestSecurityTabOperatorSeesFindings(t *testing.T) {
	t.Parallel()
	e := newSecEnv(t)
	op := e.userClient(t, "oscar", authz.RoleOperator, "192.0.2.30")
	page := result(op.get("/servers/r730xd/security")).status(t, http.StatusOK)
	page.contains(t, "Telnet is on (np).", `id="chk-svc-telnet"`, "Why it matters and what to do",
		"Can&#39;t read the account list with the read-only account.", "Dell iDRAC:",
		"2.86&lt;script&gt;alert(1)&lt;/script&gt;", "Accepted risk</span> by morgan",
		"the &lt;UPS&gt; card polls it", "Re-run checks", "needs the admin role", `rel="noopener noreferrer"`).
		lacks(t, "Accept as a risk", `action="/servers/r730xd/security/accept"`, `action="/servers/r730xd/security/rerun"`,
			"Remove acceptance", "/security/accept/remove")
	body := page.rec.Body.String()
	if strings.Index(body, "chk-svc-telnet") > strings.Index(body, "chk-svc-ssh") {
		t.Fatal("problems first within a group")
	}
}

func TestSecurityTabAdminForms(t *testing.T) {
	t.Parallel()
	e := newSecEnv(t)
	adm := e.adminClient()
	page := result(adm.get("/servers/r730xd/security")).status(t, http.StatusOK)
	page.contains(t, `action="/servers/r730xd/security/rerun"`, "Accept as a risk", `name="check" value="svc.telnet"`,
		`action="/servers/r730xd/security/accept/remove"`, "Remove acceptance").
		lacks(t, `name="check" value="svc.ssh"`)

	rec := adm.submit("/servers/r730xd/security", "/servers/r730xd/security/rerun", nil)
	result(rec).status(t, http.StatusSeeOther).location(t, "/servers/r730xd/security?done=rerun")
	result(adm.get("/servers/r730xd/security?done=rerun")).contains(t, "The checks run now")

	// The form carries the finding as shown (result and subject hash); the post sends it back.
	seen := seenOf(t, "svc.telnet")
	page.contains(t, `name="check" value="svc.telnet"><input type="hidden" name="seen" value="`+seen+`"`)
	rec = adm.submit("/servers/r730xd/security", "/servers/r730xd/security/accept",
		url.Values{"check": {"svc.telnet"}, "comment": {"isolated lab network"}, "seen": {seen}})
	result(rec).status(t, http.StatusSeeOther).location(t, "/servers/r730xd/security?done=accepted#chk-svc-telnet")
	rec = adm.submit("/servers/r730xd/security", "/servers/r730xd/security/accept/remove", url.Values{"check": {"svc.ipmi"}})
	result(rec).status(t, http.StatusSeeOther).location(t, "/servers/r730xd/security?done=unaccepted#chk-svc-ipmi")
	if len(e.sec.reruns) != 1 || e.sec.accepts[0] != "morgan/r730xd/svc.telnet/isolated lab network" || e.sec.seen[0] != seen ||
		e.sec.unaccepts[0] != "morgan/r730xd/svc.ipmi" {
		t.Fatalf("service calls %v %v %v", e.sec.reruns, e.sec.accepts, e.sec.unaccepts)
	}
}

func TestSecurityChangeRefusals(t *testing.T) {
	t.Parallel()
	e := newSecEnv(t)
	adm := e.adminClient()
	result(adm.submit("/servers/r730xd/security", "/servers/r730xd/security/accept",
		url.Values{"check": {"svc.telnet"}, "comment": {""}, "seen": {seenOf(t, "svc.telnet")}})).status(t, http.StatusUnprocessableEntity).contains(t, "Say why the risk is accepted.")
	result(adm.submit("/servers/r730xd/security", "/servers/r730xd/security/accept",
		url.Values{"check": {"../etc"}, "comment": {"x"}, "seen": {seenOf(t, "svc.telnet")}})).status(t, http.StatusBadRequest)
	result(adm.submit("/servers/r730xd/security", "/servers/r730xd/security/accept/remove",
		url.Values{"check": {"svc.snmp"}})).status(t, http.StatusNotFound)
	e.sec.acceptErr = bmcsec.ErrNotProblem
	result(adm.submit("/servers/r730xd/security", "/servers/r730xd/security/accept",
		url.Values{"check": {"svc.telnet"}, "comment": {"x"}, "seen": {seenOf(t, "svc.telnet")}})).status(t, http.StatusConflict)
	e.sec.rerunErr = &bmcsec.CooldownError{Left: 90 * time.Second}
	rec := adm.submit("/servers/r730xd/security", "/servers/r730xd/security/rerun", nil)
	result(rec).status(t, http.StatusTooManyRequests).contains(t, "Try again in 90 seconds")
	if rec.Header().Get("Retry-After") != "90" {
		t.Fatalf("Retry-After %q", rec.Header().Get("Retry-After"))
	}
	e.sec.rerunErr = fleet.ErrPaused
	result(adm.submit("/servers/r730xd/security", "/servers/r730xd/security/rerun", nil)).status(t, http.StatusConflict).
		contains(t, "paused")
	e.sec.rerunErr = fleet.ErrUnknownServer // removed since the page was loaded
	result(adm.submit("/servers/r730xd/security", "/servers/r730xd/security/rerun", nil)).status(t, http.StatusNotFound)
	e.sec.rerunErr = errors.New("boom")
	result(adm.submit("/servers/r730xd/security", "/servers/r730xd/security/rerun", nil)).status(t, http.StatusInternalServerError)

	op := e.userClient(t, "oscar", authz.RoleOperator, "192.0.2.30")
	tok := e.csrfToken(op)
	result(op.do(http.MethodPost, "/servers/r730xd/security/rerun", url.Values{csrfField: {tok}})).status(t, http.StatusForbidden)
	result(op.do(http.MethodPost, "/servers/r730xd/security/accept",
		url.Values{csrfField: {tok}, "check": {"svc.telnet"}, "comment": {"x"}, "seen": {seenOf(t, "svc.telnet")}})).status(t, http.StatusForbidden)
	if _, ok := e.findAudit(string(authz.SecurityRerun), "denied"); !ok {
		t.Fatal("a refused re-run is audited")
	}
	result(adm.do(http.MethodPost, "/servers/nope/security/rerun", url.Values{csrfField: {e.csrfToken(adm)}})).status(t, http.StatusNotFound)
}

func TestSecurityTabStates(t *testing.T) {
	t.Parallel()
	e := newSecEnv(t)
	adm := e.adminClient()
	result(adm.get("/servers/r240/security")).status(t, http.StatusOK).contains(t, "Running now", "Not checked yet")
	result(adm.get("/servers/spare/security")).status(t, http.StatusOK).contains(t, "Security checks are off for this server")
	e.sec.status["r730xd"] = bmcsec.RunStatus{Enabled: true, HasReport: true, AsOf: secAt, Error: bmc.ClassTimeout,
		Overdue: true, Requested: true, CooldownLeft: 3 * time.Minute}
	result(adm.get("/servers/r730xd/security")).contains(t, "The last run failed (timed out)", "A run was requested",
		"overdue", "Re-run: a run is already on its way.").lacks(t, `action="/servers/r730xd/security/rerun"`)
	e.sec.status["r730xd"] = bmcsec.RunStatus{Enabled: true, HasReport: true, AsOf: secAt, CooldownLeft: 150 * time.Second}
	result(adm.get("/servers/r730xd/security")).contains(t, "available again in 3 minutes")
	result(adm.get("/servers/nope/security")).status(t, http.StatusNotFound)
}

func TestSecurityHiddenWithoutTheService(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t)
	adm := e.adminClient()
	result(adm.get("/servers/r730xd")).status(t, http.StatusOK).lacks(t, "/servers/r730xd/security")
	result(adm.get("/servers/r730xd/security")).status(t, http.StatusNotFound)
	result(adm.get("/")).lacks(t, `<th scope="col">Security</th>`)
}

func TestFleetSecurityColumn(t *testing.T) {
	t.Parallel()
	e := newSecEnv(t)
	viewer := e.userClient(t, "vera", authz.RoleViewer, "192.0.2.31")
	for _, path := range []string{"/servers"} {
		page := result(viewer.get(path)).status(t, http.StatusOK)
		page.contains(t, `<th scope="col">Security</th>`, `href="/servers/r730xd/security"`, "1 fail · 1 warn",
			`data-label="Security"`, "Checking now", `<span class="meta">Disabled</span>`).lacks(t, `<span class="meta">Off</span>`)
	}
	result(viewer.get("/servers/r730xd")).contains(t, `href="/servers/r730xd/security"`)
}

// seenOf is the "seen" value of a check's finding in testReport (result|subject hash).
func seenOf(t *testing.T, check string) string {
	t.Helper()
	f, ok := testReport().Finding(check)
	if !ok {
		t.Fatalf("no finding %s", check)
	}
	return f.Seen()
}

// TestAcceptNeedsTheFindingAsShown: an accept form without a well-formed "seen" is a bad
// request, and a finding that changed since the page was loaded is refused with the tab
// re-rendered and a notice, nothing accepted.
func TestAcceptNeedsTheFindingAsShown(t *testing.T) {
	t.Parallel()
	e := newSecEnv(t)
	adm := e.adminClient()
	const tab, action = "/servers/r730xd/security", "/servers/r730xd/security/accept"
	for _, bad := range []string{"", "warn", "warn|short", "pass|" + strings.Repeat("0", 64), "warn|" + strings.Repeat("g", 64)} {
		result(adm.submit(tab, action, url.Values{"check": {"svc.telnet"}, "comment": {"x"}, "seen": {bad}})).status(t, http.StatusBadRequest)
	}
	e.sec.acceptErr = bmcsec.ErrChanged
	page := result(adm.submit(tab, action, url.Values{"check": {"svc.telnet"}, "comment": {"x"}, "seen": {seenOf(t, "svc.telnet")}}))
	page.status(t, http.StatusConflict).contains(t, "This finding changed since the page was loaded; review it again.",
		"BMC security checks", `id="chk-svc-telnet"`, `role="alert"`)
	if len(e.sec.accepts) != 0 {
		t.Fatalf("accepted although the finding changed: %v", e.sec.accepts)
	}
}

// mostlyUnknownReport is a run that could evaluate almost nothing: no problem found, but
// no reassurance either.
func mostlyUnknownReport() bmcsec.Report {
	return bmcsec.Evaluate("r240", bmc.Posture{Started: secAt}, bmcsec.Inputs{Kind: "idrac8"}, secAt)
}

// TestMostlyUnknownIsNotOK: a run whose checks mostly could not be evaluated is shown as
// unknown, on the tab and in the fleet column, never as a green "OK".
func TestMostlyUnknownIsNotOK(t *testing.T) {
	t.Parallel()
	e := newSecEnv(t)
	e.sec.reports["r240"] = mostlyUnknownReport()
	e.sec.status["r240"] = bmcsec.RunStatus{Enabled: true, HasReport: true, AsOf: secAt}
	adm := e.adminClient()
	result(adm.get("/servers/r240/security")).status(t, http.StatusOK).
		contains(t, "Most checks could not be evaluated", `b-unknown`).lacks(t, "No failing checks and no warnings.", `class="panel p-ok"`)
	page := result(adm.get("/servers")).status(t, http.StatusOK)
	body := page.rec.Body.String()
	cell := body[strings.Index(body, `href="/servers/r240/security"`):]
	cell = cell[:strings.Index(cell, "</a>")]
	if !strings.Contains(cell, "Unknown") || strings.Contains(cell, "OK") || !strings.Contains(cell, "b-unknown") {
		t.Fatalf("fleet cell %q", cell)
	}
}

// TestFailedRunTextWithoutAnEarlierRun: "the results shown are from the run before" is
// only said when there is a run before.
func TestFailedRunTextWithoutAnEarlierRun(t *testing.T) {
	t.Parallel()
	e := newSecEnv(t)
	e.sec.status["r240"] = bmcsec.RunStatus{Enabled: true, Error: bmc.ClassTimeout}
	adm := e.adminClient()
	result(adm.get("/servers/r240/security")).status(t, http.StatusOK).
		contains(t, "The last run failed (timed out).", "Not checked yet").lacks(t, "from the run before")
	e.sec.status["r730xd"] = bmcsec.RunStatus{Enabled: true, HasReport: true, AsOf: secAt, Error: bmc.ClassTimeout}
	result(adm.get("/servers/r730xd/security")).contains(t, "The last run failed (timed out). The results shown are from the run before.")
}

// TestAcceptedCommentWrapsAndSaysItsLimit: a long accepted comment cannot widen the page,
// and the form says the limit is in bytes.
func TestAcceptedCommentWrapsAndSaysItsLimit(t *testing.T) {
	t.Parallel()
	e := newSecEnv(t)
	adm := e.adminClient()
	result(adm.get("/static/app.css")).contains(t, ".acked { margin: 0; overflow-wrap: anywhere; }")
	result(adm.get("/servers/r730xd/security")).contains(t, `maxlength="500"`, "500 bytes at most", "sent to notification targets")
}

// TestSecurityTabPostureMapAndQuietChecks (plan 04 §11, slice C): operators and admins
// get the posture map as the group jump list, and passes fold into "N more checks";
// viewers keep the summary only.
func TestSecurityTabPostureMapAndQuietChecks(t *testing.T) {
	t.Parallel()
	e := newSecEnv(t)
	adm := e.adminClient()
	page := result(adm.get("/servers/r730xd/security")).status(t, http.StatusOK)
	page.contains(t, `<nav class="secmap-nav" aria-label="Check groups">`, `<li class="secmap-g g-`, `href="#g-`,
		`<span class="pm pm-`, `class="more chk-quiet"`, " more check").lacks(t, "style=")
	body := page.rec.Body.String()
	quiet := between(body, `class="more chk-quiet"`, "</details>")
	if strings.Contains(quiet, "b-crit") || strings.Contains(quiet, "b-warn") {
		t.Fatalf("a failing or warning finding was folded away:\n%s", quiet)
	}
	viewer := e.userClient(t, "vera", authz.RoleViewer, "192.0.2.31")
	result(viewer.get("/servers/r730xd/security")).lacks(t, "secmap", "chk-quiet")
}

package ui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/console"
)

func consoleHarness(t *testing.T, role authz.Role, tweak ...func(*Deps)) (*harness, *client, *fakeConsoles, *fakeKVM) {
	t.Helper()
	fc, fk := newFakeConsoles(), &fakeKVM{available: map[string]bool{"r240": true}}
	all := append([]func(*Deps){func(d *Deps) {
		d.Consoles, d.KVM = fc, fk
		d.BMCWebURL = func(id string) string { return "https://192.0.2.10/" }
	}}, tweak...)
	h := newHarness(t, all...)
	h.fleet.servers[1] = withKVMCapability(h.fleet.servers[1])
	secret := h.addUser("boss", role, true)
	c := h.client("192.0.2.5")
	c.login("boss", secret)
	return h, c, fc, fk
}

func TestServerPageShowsConsoleCard(t *testing.T) {
	t.Parallel()
	_, admin, _, _ := consoleHarness(t, authz.RoleAdmin)
	result(admin.get("/servers/r730xd")).status(t, http.StatusOK).contains(t,
		`<h2 id="gc-h">Graphical console</h2>`, `href="/servers/r730xd/console">Open console</a>`,
		"VNC over TLS to the BMC.", `<a class="mi" href="/servers/r730xd/console">`).
		lacks(t, "Graphical console</strong>: not available yet")
	result(admin.get("/servers/r240")).contains(t, `action="/servers/r240/console/kvm-launch"`,
		"Open native iDRAC console").lacks(t, "Open console</a>")

	_, viewer, _, _ := consoleHarness(t, authz.RoleViewer)
	result(viewer.get("/servers/r730xd")).contains(t, "Graphical console", "Needs the admin role.").
		lacks(t, "/console\">Open console", "kvm-launch")
}

func TestConsolePageNeedsAdminAndFreshStepUp(t *testing.T) {
	t.Parallel()
	h, admin, _, _ := consoleHarness(t, authz.RoleAdmin)
	result(admin.get("/servers/r730xd/console")).status(t, http.StatusOK).
		contains(t, `action="/servers/r730xd/console"`, ">Connect</button>").lacks(t, "data-ticket", "console.js")
	h.clock.Advance(6 * time.Minute)
	result(admin.get("/servers/r730xd/console")).status(t, http.StatusSeeOther).
		location(t, "/stepup?next=%2Fservers%2Fr730xd%2Fconsole")
	if _, ok := h.audit.find("console.vnc", "denied"); !ok {
		t.Error("stale step-up not audited")
	}
	result(admin.get("/servers/r240/console")).status(t, http.StatusSeeOther) // stale first
	_, viewer, _, _ := consoleHarness(t, authz.RoleViewer)
	result(viewer.get("/servers/r730xd/console")).status(t, http.StatusForbidden)
	_, a2, _, _ := consoleHarness(t, authz.RoleAdmin)
	result(a2.get("/servers/r240/console")).status(t, http.StatusNotFound) // not configured
	result(a2.get("/servers/nope/console")).status(t, http.StatusNotFound)
}

func consoleCSRF(t *testing.T, c *client, path string) string {
	t.Helper()
	return csrfFor(t, c.get(path).Body.String(), "/servers/r730xd/console")
}

func TestConsoleStartIssuesTicketAndRendersPage(t *testing.T) {
	t.Parallel()
	_, c, fc, _ := consoleHarness(t, authz.RoleAdmin)
	tok := consoleCSRF(t, c, "/servers/r730xd/console")
	rec := c.do(http.MethodPost, "/servers/r730xd/console", url.Values{csrfField: {tok}})
	result(rec).status(t, http.StatusOK).contains(t, `data-ticket="tkt-r730xd"`,
		`data-ws="/servers/r730xd/console/ws"`, `<script type="module" src="/static/console.js?v=dev"></script>`,
		`role="toolbar" aria-label="Console controls"`, "Send Ctrl-Alt-Del", "View only", "Disconnect")
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
	if strings.Count(rec.Body.String(), "<script") != 3 || strings.Contains(rec.Body.String(), "nonce=") {
		t.Error("only the two enhancement scripts (app.js, palette.js) and the one external module script are allowed")
	}
	g, ok := fc.lastGrant()
	if !ok || g.ServerID != "r730xd" || g.Username != "boss" || g.Takeover || g.SrcIP != "192.0.2.5" ||
		g.Session != console.SessionHash(c.jar[auth.SessionCookieName]) {
		t.Errorf("grant = %+v", g)
	}

	rec = c.do(http.MethodPost, "/servers/r730xd/console", url.Values{csrfField: {tok}, "takeover": {"1"}})
	result(rec).status(t, http.StatusOK)
	if g, _ := fc.lastGrant(); !g.Takeover {
		t.Error("takeover not passed on")
	}
	result(c.do(http.MethodPost, "/servers/r730xd/console", url.Values{csrfField: {"forged"}})).status(t, http.StatusForbidden)
}

func TestConsoleStartErrors(t *testing.T) {
	t.Parallel()
	h, c, fc, _ := consoleHarness(t, authz.RoleAdmin)
	tok := consoleCSRF(t, c, "/servers/r730xd/console")
	fc.issueErr = &console.InUseError{Active: console.Active{Username: "alice", Since: h.clock.Now()}}
	fc.status["r730xd"] = console.Status{Configured: true, HasPassword: true, InUse: true,
		Active: console.Active{Username: "alice", Since: h.clock.Now()}}
	result(c.do(http.MethodPost, "/servers/r730xd/console", url.Values{csrfField: {tok}})).
		status(t, http.StatusConflict).contains(t, "in use by alice", "Take over console", `name="takeover" value="1"`)
	for err, code := range map[error]int{console.ErrNoPassword: 409, console.ErrCoolingDown: 429,
		console.ErrNotConfigured: 404, errFakeBMC: 503} {
		fc.issueErr = err
		result(c.do(http.MethodPost, "/servers/r730xd/console", url.Values{csrfField: {tok}})).status(t, code)
	}
	if _, ok := h.audit.find("console.vnc", "denied"); !ok {
		t.Error("refusal not audited")
	}
}

func TestConsoleStartRateLimitAndStaleStepUp(t *testing.T) {
	t.Parallel()
	h, c, _, _ := consoleHarness(t, authz.RoleAdmin, func(d *Deps) { d.ConsolePerUser = RateLimit{Events: 2, Per: time.Minute} })
	tok := consoleCSRF(t, c, "/servers/r730xd/console")
	for range 2 {
		result(c.do(http.MethodPost, "/servers/r730xd/console", url.Values{csrfField: {tok}})).status(t, http.StatusOK)
	}
	result(c.do(http.MethodPost, "/servers/r730xd/console", url.Values{csrfField: {tok}})).status(t, http.StatusTooManyRequests)
	h.clock.Advance(10 * time.Minute)
	result(c.do(http.MethodPost, "/servers/r730xd/console", url.Values{csrfField: {tok}})).
		status(t, http.StatusSeeOther).location(t, "/stepup?next=%2Fservers%2Fr730xd%2Fconsole")
}

func TestConsoleRoutesHiddenWithoutBroker(t *testing.T) {
	t.Parallel()
	_, c := signedInAdmin(t)
	result(c.get("/servers/r730xd/console")).status(t, http.StatusNotFound)
	result(c.do(http.MethodPost, "/servers/r730xd/console", url.Values{})).status(t, http.StatusNotFound)
	result(c.get("/servers/r730xd/console/ws?ticket=x")).status(t, http.StatusNotFound)
	result(c.get("/servers/r730xd")).lacks(t, "gc-h")
}

func TestKVMLaunch(t *testing.T) {
	t.Parallel()
	h, c, _, fk := consoleHarness(t, authz.RoleAdmin)
	page := c.get("/servers/r240").Body.String()
	tok := csrfFor(t, page, "/servers/r240/console/kvm-launch")
	rec := c.do(http.MethodPost, "/servers/r240/console/kvm-launch", url.Values{csrfField: {tok}})
	result(rec).status(t, http.StatusOK).contains(t, `id="kvm-link" href="https://192.0.2.11/console?tempPassword=Tmp-pass-1&amp;tempUsername=tmpkvm1&amp;username=oob_op"`)
	if rec.Header().Get("Cache-Control") != "no-store" || fk.launches != 1 {
		t.Errorf("no-store %q launches %d", rec.Header().Get("Cache-Control"), fk.launches)
	}
	if e, ok := h.audit.find("console.kvm_launch", "ok"); !ok || e.ServerID != "r240" {
		t.Errorf("audit = %+v %v", e, ok)
	}
	for _, e := range h.audit.entries {
		for _, v := range e.Params {
			if s, _ := v.(string); strings.Contains(s, "Tmp-pass") {
				t.Fatal("temporary credential in the audit log")
			}
		}
	}
	fk.err = errFakeBMC
	result(c.do(http.MethodPost, "/servers/r240/console/kvm-launch", url.Values{csrfField: {tok}})).status(t, http.StatusBadGateway)
	if _, ok := h.audit.find("console.kvm_launch", "error"); !ok {
		t.Error("failed launch not audited")
	}
	result(c.do(http.MethodPost, "/servers/r730xd/console/kvm-launch", url.Values{csrfField: {tok}})).status(t, http.StatusNotFound)
	result(c.do(http.MethodPost, "/servers/r240/console/kvm-launch", url.Values{csrfField: {"bad"}})).status(t, http.StatusForbidden)
}

// A BMC that offers the native launch but has no operator login configured: the button
// is shown disabled (direction B C-10: aria-disabled + visible .why-off reason), never
// as a form.
func TestServerPageExplainsMissingNativeLaunch(t *testing.T) {
	t.Parallel()
	_, admin, _, fk := consoleHarness(t, authz.RoleAdmin)
	fk.mu.Lock()
	fk.available = map[string]bool{}
	fk.mu.Unlock()
	result(admin.get("/servers/r240")).status(t, http.StatusOK).
		contains(t, "native iDRAC console launch is not offered", "credentials.operator",
			`<span class="btn btn-disabled btn-small" aria-disabled="true" aria-describedby="kvm-why">Open native iDRAC console</span>`,
			`<span id="kvm-why" class="why-off">`).
		lacks(t, "kvm-launch")
	result(admin.get("/servers/r730xd")).lacks(t, "native iDRAC console launch is not offered")
}

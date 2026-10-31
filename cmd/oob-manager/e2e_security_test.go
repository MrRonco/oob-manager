//go:build e2e

package main

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/notify"
)

// e2eSecurityYAML turns /metrics on and sets a minimum known good firmware per kind: the
// R730XD mock (iDRAC8 2.86.86.86) meets it, the R240 mock (iDRAC9 7.00.00.182) does not.
const e2eSecurityYAML = e2eMetricsYAML + "security: { min_firmware: { idrac8: \"2.86.86.86\", idrac9: \"7.10.30.00\" } }\n"

// checkSecurity drives the BMC security checks through the real stack (tech_doc §31): the
// run at startup reads both mocks and probes the fakes; the Security tab shows the
// findings and what to do; an accepted risk stops counting until it is removed; a re-run
// reaches the poller and a second one inside the cooldown is refused; /metrics, the
// fleet table and the webhook carry the results. The whole flow sends the BMCs reads only.
func checkSecurity(t *testing.T) {
	s := startStackWith(t, "127.0.0.1:0", e2eSecurityYAML)
	b := browser{t: t, base: s.base, c: s.client(t)}
	login(t, b, s)
	var p page
	waitFor(t, "the first security check runs", func() bool {
		p = b.get("/servers/r730xd/security")
		return strings.Contains(p.body, "Last run") && strings.Contains(b.get("/servers/r240/security").body, "Last run")
	})
	expectPage(t, p, "BMC security checks", "TLS and SSH", "Web certificate expiry", "VNC port certificate",
		"Not checked: an iDRAC8 takes one VNC client at a time",
		"Key exchange: only diffie-hellman-group14-sha1", "Port 80 redirects to HTTPS", "WS-Management is on",
		"Enabled with a factory default name: root.", "minimum known good 2.86.86.86", "Dell iDRAC:", "Re-run checks")
	expectPage(t, b.get("/servers/r240/security"), "older than the minimum known good 7.10.30.00")
	checkSecurityAccept(t, b)
	checkSecurityRerun(t, b, s)
	checkSecurityOutputs(t, b, s)
	assertSecurityReadOnly(t, s)
	if code := s.stop(); code != 0 {
		t.Fatalf("serve exit %d", code)
	}
	assertAudited(t, s.dbPath, "server.security.accept", "server.security.unaccept", "server.security.rerun")
}

var warnCount = regexp.MustCompile(`<dt>Warning</dt><dd>(\d+)</dd>`)

func warnings(t *testing.T, p page) string {
	t.Helper()
	m := warnCount.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatal("no warning count on the Security tab")
	}
	return m[1]
}

// checkSecurityAccept accepts the default-name finding as a risk with a comment, sees it
// stop counting, and removes the acceptance again.
func checkSecurityAccept(t *testing.T, b browser) {
	t.Helper()
	const tab = "/servers/r730xd/security"
	first := b.get(tab)
	before := warnings(t, first)
	seen := formSeen(t, first, "acct.default_names")
	expectRedirect(t, b.submit(tab, tab+"/accept", url.Values{"check": {"acct.default_names"}, "seen": {seen},
		"comment": {"Lab BMC; the factory password was changed"}}), tab+"?done=accepted#chk-acct-default_names")
	p := b.get(tab + "?done=accepted")
	expectPage(t, p, "Finding accepted as a risk.", "by admin on", "Lab BMC; the factory password was changed",
		"<dt>Accepted risk</dt><dd>1</dd>", "Remove acceptance")
	if warnings(t, p) == before {
		t.Fatal("an accepted finding still counts as a warning")
	}
	expectRedirect(t, b.submit(tab, tab+"/accept/remove", url.Values{"check": {"acct.default_names"}}),
		tab+"?done=unaccepted#chk-acct-default_names")
	if got := warnings(t, b.get(tab)); got != before {
		t.Fatalf("warnings after removing the acceptance: %s, want %s", got, before)
	}
	// Only a warning or a failure can be accepted.
	if passing := b.submit(tab, tab+"/accept", url.Values{"check": {"svc.telnet"}, "comment": {"x"}, "seen": {seen}}); passing.status != http.StatusConflict {
		t.Fatalf("accepting a passing check: %d", passing.status)
	}
	// A form that shows another state of the finding (here: another subject) accepts nothing.
	stale := strings.SplitN(seen, "|", 2)[0] + "|" + strings.Repeat("0", 64)
	p = b.submit(tab, tab+"/accept", url.Values{"check": {"acct.default_names"}, "comment": {"x"}, "seen": {stale}})
	if p.status != http.StatusConflict || !strings.Contains(p.body, "This finding changed since the page was loaded") {
		t.Fatalf("stale form: %d", p.status)
	}
	if got := warnings(t, b.get(tab)); got != before {
		t.Fatalf("a stale form accepted something: %s warnings, want %s", got, before)
	}
}

// checkSecurityRerun asks for a run now: the poller runs it, and a second request inside
// the cooldown is refused with Retry-After.
func checkSecurityRerun(t *testing.T, b browser, s *stack) {
	t.Helper()
	const tab = "/servers/r240/security"
	heads := s.mocks["r240"].Heads()
	expectRedirect(t, b.submit(tab, tab+"/rerun", nil), tab+"?done=rerun")
	expectPage(t, b.get(tab+"?done=rerun"), "Re-run requested.")
	waitFor(t, "the re-run reaches the BMC", func() bool { return s.mocks["r240"].Heads() > heads })
	// The tab now shows the button disabled; the token comes from the other server's form.
	csrf := url.Values{"csrf_token": {formCSRF(t, b.get("/servers/r730xd/security"), "/servers/r730xd/security/rerun")}}
	p := b.post(tab+"/rerun", csrf)
	if p.status != http.StatusTooManyRequests || p.header.Get("Retry-After") == "" {
		t.Fatalf("second re-run: %d %q", p.status, p.header.Get("Retry-After"))
	}
}

// checkSecurityOutputs: the fleet table, /metrics and the webhook carry the results.
func checkSecurityOutputs(t *testing.T, b browser, s *stack) {
	t.Helper()
	expectPage(t, b.get("/servers"), `href="/servers/r730xd/security"`, `href="/servers/r240/security"`, " warn")
	m := scrape(t, b, s)
	expectPage(t, m, `oob_security_checks{server="r730xd",result="warn"}`, `oob_security_checks{server="r240",result="pass"}`,
		`oob_tls_cert_expiry_timestamp_seconds{server="r730xd",port="443"}`,
		`oob_tls_cert_expiry_timestamp_seconds{server="r240",port="443"}`)
	// The iDRAC8's VNC port is never probed, so it has no certificate to report.
	if strings.Contains(m.body, `oob_tls_cert_expiry_timestamp_seconds{server="r730xd",port="5901"}`) {
		t.Error("a certificate expiry was reported for the iDRAC8's VNC port, which the checks must not open")
	}
	// The service looks for new findings every 15 s: the first pass at startup comes before
	// any check has run, so the message follows the second. The accepted risk and its
	// removal (checkSecurityAccept) come through the audit tap.
	deadline := time.Now().Add(45 * time.Second)
	for !s.hooks.has(notify.ClassSecurity, "new BMC security findings") || !s.hooks.has(notify.ClassSecurity, "Accepted risk: Default account names") ||
		!s.hooks.has(notify.ClassSecurity, "Accepted risk ended: Default account names") {
		if time.Now().After(deadline) {
			t.Fatal("no security notification")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// assertSecurityReadOnly: everything the BMCs received was a read. Redfish: GET and HEAD
// plus the poller's own session login (logout comes at shutdown); port 80: HEAD or GET;
// SSH: handshakes only, no login; VNC: the iDRAC8's port never opened by the checks (its
// single-client server stays busy after each connection) and no VNC authentication.
func assertSecurityReadOnly(t *testing.T, s *stack) {
	t.Helper()
	for id, m := range s.mocks {
		for _, r := range m.Requests() {
			login := r.Method == http.MethodPost && r.Path == m.SessionsURI()
			if r.Method != http.MethodGet && r.Method != http.MethodHead && !login {
				t.Errorf("%s received %s %s", id, r.Method, r.Path)
			}
		}
		if m.OtherWrites() != 0 || m.SessionStats().Created != 1 || m.Heads() < 2 {
			t.Errorf("%s: writes %d, sessions %+v, HEADs %d", id, m.OtherWrites(), m.SessionStats(), m.Heads())
		}
		if ssh := s.ssh[id]; ssh.AuthAttempts() != 0 || ssh.Sessions() != 0 {
			t.Errorf("%s: the SSH probe logged in (%d attempts)", id, ssh.AuthAttempts())
		}
	}
	methods := s.plain.seen()
	if len(methods) == 0 || slices.ContainsFunc(methods, func(m string) bool { return m != http.MethodHead && m != http.MethodGet }) {
		t.Errorf("port 80 received %v", methods)
	}
	// The counter is wired (the web port was dialled), and the iDRAC8's VNC port never was.
	if web, vnc := s.probeDials.count("192.0.2.10:443"), s.probeDials.count("192.0.2.10:5901"); web == 0 || vnc != 0 {
		t.Errorf("security probe dials: web port %d (want > 0), iDRAC8 VNC port %d (want 0)", web, vnc)
	}
	if st := s.vnc.Stats(); st.AuthOK != 0 {
		t.Errorf("VNC authentication during the security checks: %+v", st)
	}
}

// formSeen is the hidden "seen" value (result and subject hash) of a check's accept form.
func formSeen(t *testing.T, p page, check string) string {
	t.Helper()
	re := regexp.MustCompile(`name="check" value="` + regexp.QuoteMeta(check) + `"><input type="hidden" name="seen" value="([^"]+)"`)
	m := re.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("no accept form for %s", check)
	}
	return m[1]
}

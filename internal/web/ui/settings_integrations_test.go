package ui

// repopolicy:allow private-addresses -- tests the private-network hints and checks of the Integrations page

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/config"
	"oob-manager/internal/integrations"
	"oob-manager/internal/settings"
	"oob-manager/internal/store"
	"oob-manager/internal/tlspin/tlspintest"
	"oob-manager/internal/tofu"
	"oob-manager/internal/web"
)

// gelfRecv is a GELF input that counts frames (plain TCP, or TLS when cert is set).
type gelfRecv struct {
	addr   string
	frames chan string
}

func newGELFRecv(t *testing.T, cert *tls.Certificate) *gelfRecv {
	t.Helper()
	var ln net.Listener
	var err error
	if cert != nil {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12})
	} else {
		ln, err = (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	}
	must(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	g := &gelfRecv{addr: ln.Addr().String(), frames: make(chan string, 100)}
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					f, rerr := br.ReadBytes(0)
					if rerr != nil {
						return
					}
					g.frames <- string(f)
				}
			}()
		}
	}()
	return g
}

type gelfEnv struct {
	*settingsEnv
	set   *settings.Service
	svc   *integrations.Service
	plain *gelfRecv
	tls   *gelfRecv
	pair  tlspintest.Pair
}

// The configured GELF addresses (inside the default private ranges) and where the
// test dialer sends them.
const (
	plainGELF = "10.9.0.30:12201"
	tlsGELF   = "10.9.0.31:6514"
)

func newGELFEnv(t *testing.T, extraYAML string, tweak ...func(*Deps)) *gelfEnv {
	t.Helper()
	e := newSettingsEnv(t)
	g := &gelfEnv{settingsEnv: e, pair: tlspintest.Issued(t)}
	cert := g.pair.TLS()
	g.plain, g.tls = newGELFRecv(t, nil), newGELFRecv(t, &cert)
	file, err := config.Parse([]byte(extraYAML + generalBaseYAML))
	must(t, err)
	lg := audit.NewLogger(e.db.Audit(), nil, e.clock.Now, quiet())
	g.set, err = settings.New(context.Background(), settings.Config{DB: e.db, Audit: lg, File: file, Now: e.clock.Now, Logger: quiet()})
	must(t, err)
	routes := map[string]string{plainGELF: g.plain.addr, tlsGELF: g.tls.addr}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if to, ok := routes[addr]; ok {
			return (&net.Dialer{}).DialContext(ctx, network, to)
		}
		return nil, errors.New("test: no route")
	}
	g.svc, err = integrations.New(integrations.Config{Settings: g.set, Audit: lg, Switch: &audit.SwitchSink{},
		Policy: integrations.Policy{Allowed: file.GELFNetworks()}, Dial: dial, Logger: quiet(),
		Tuning: audit.ShipperConfig{DialTimeout: time.Second, WriteTimeout: time.Second, FlushTimeout: 200 * time.Millisecond}})
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.svc.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	prover, err := tofu.NewProver([]byte(strings.Repeat("t", 32)), e.clock.Now)
	must(t, err)
	e.deps.Settings, e.deps.Integrations, e.deps.Proofs = g.set, g.svc, prover
	e.deps.Hints = Hints{MetricsEnabled: true, MetricsNetworks: []string{"192.0.2.40/32"}}
	for _, fn := range tweak {
		fn(&e.deps)
	}
	app, err := New(e.deps)
	must(t, err)
	e.handler, err = web.NewHandler(app, web.Options{Logger: quiet()})
	must(t, err)
	return g
}

func enableForm(addr string) url.Values {
	return url.Values{"gelf.enabled": {"on"}, "gelf.address": {addr}, "gelf.transport": {"tcp"}, "gelf.server_name": {""},
		"gelf.pin_sha256": {""}}
}

func TestIntegrationsPageDisabledWithHints(t *testing.T) {
	t.Parallel()
	g := newGELFEnv(t, "")
	c := g.adminClient()
	r := result(c.get(pathIntegrations)).status(t, http.StatusOK).contains(t,
		`aria-current="page">Integrations`, "Audit shipping (GELF)", "Disabled", "No fingerprint pinned.",
		"https://oob.test/api/v1/servers/r730xd", "Authorization: Bearer &lt;token&gt;", "https://oob.test/readyz",
		"Keyword:      ok", `targets: [&#34;oob.test&#34;]`, "credentials_file", "192.0.2.40/32",
		`oob_server_up{server=&#34;r730xd&#34;} 1`, "metrics are file-only", "10.0.0.0/8, 172.16.0.0/12",
		`href="/settings/notifications"`, "Save and apply", "Fetch and confirm the certificate", `data-copy="hint-prom"`)
	r.lacks(t, "Send test", "oobk_")
	// Tokens minted in this install never reach the page.
	must(t, g.db.Users().Create(context.Background(), store.User{ID: "u-tokowner", Username: "tokowner", Role: store.RoleViewer,
		PwHash: "x", CreatedAt: g.clock.Now()}))
	raw, _, err := g.tokens.Issue(context.Background(), "prometheus", "u-tokowner")
	must(t, err)
	if strings.Contains(c.get(pathIntegrations).Body.String(), raw) {
		t.Fatal("a token reached the Integrations page")
	}
}

func TestIntegrationsSaveApplyAndTest(t *testing.T) {
	t.Parallel()
	g := newGELFEnv(t, "")
	c := g.adminClient()
	result(postGELF(t, c, pathIntegrations, enableForm(plainGELF))).status(t, http.StatusSeeOther).
		location(t, pathIntegrations+"?done=saved")
	if rec, ok := g.findAudit(settings.ActionIntegrationsUpdate, audit.ResultOK); !ok || !strings.Contains(rec.ParamsJSON, plainGELF) {
		t.Fatalf("update row %+v", rec)
	}
	waitUntil(t, func() bool { return g.svc.Stats().Active })
	result(postGELF(t, c, pathGELFTest, nil)).status(t, http.StatusSeeOther).
		location(t, pathIntegrations+"?done=test-ok")
	result(c.get(pathIntegrations+"?done=test-ok")).status(t, http.StatusOK).contains(t, "Connected", "Test sent",
		"plain TCP, unencrypted", "Send test", plainGELF)
	if _, ok := g.findAudit(integrations.ActionTest, audit.ResultOK); !ok {
		t.Fatal("test not audited")
	}
	// Three tests a minute: the next two pass, the fourth is refused and audited.
	for range 2 {
		postGELF(t, c, pathGELFTest, nil)
	}
	result(postGELF(t, c, pathGELFTest, nil)).status(t, http.StatusTooManyRequests)
	if rec, ok := g.findAudit(integrations.ActionTest, audit.ResultDenied); !ok || rec.ErrorClass != "rate_limited" {
		t.Fatalf("rate limit not audited: %+v", rec)
	}
	// A failed test reports its class.
	result(c.get(pathIntegrations+"?done=test-failed-dial")).contains(t, "Test failed: The log server did not accept the connection.")
	result(c.get(pathIntegrations+"?done=test-failed-bogus")).lacks(t, "Test failed")
}

func TestIntegrationsRefusals(t *testing.T) {
	t.Parallel()
	g := newGELFEnv(t, "")
	c := g.adminClient()
	result(postGELF(t, c, pathIntegrations, enableForm("127.0.0.1:12201"))).status(t, http.StatusUnprocessableEntity).
		contains(t, "Not saved:", `id="i-gelf-address" name="gelf.address" type="text" autocomplete="off" spellcheck="false" value="127.0.0.1:12201"`, `aria-invalid="true"`)
	form := enableForm(plainGELF)
	form.Set("gelf.transport", "tls")
	result(postGELF(t, c, pathIntegrations, form)).status(t, http.StatusUnprocessableEntity).contains(t, "pin_sha256 is required")
	form = enableForm(plainGELF)
	form.Set("rev", "7")
	result(c.do(http.MethodPost, pathIntegrations, withCSRF(t, c, form))).status(t, http.StatusConflict)
	form = enableForm(plainGELF)
	form.Set("rev", "x")
	result(c.do(http.MethodPost, pathIntegrations, withCSRF(t, c, form))).status(t, http.StatusBadRequest)
	if g.svc.Stats().Active {
		t.Fatal("a refused change was applied")
	}
	result(postGELF(t, c, pathGELFTest, nil)).status(t, http.StatusSeeOther).location(t, pathIntegrations+"?done=test-failed-disabled")
	viewer := g.signInViewer(t, "victor", "192.0.2.21")
	result(viewer.get(pathIntegrations)).status(t, http.StatusForbidden)
	if rec, ok := g.findAudit(string(authz.AdminIntegrations), audit.ResultDenied); !ok || rec.Principal != "victor" {
		t.Fatalf("viewer refusal not audited: %+v", rec)
	}
	// After the step-up window, a change goes to the step-up page.
	g.clock.Advance(6 * time.Minute)
	stale := postGELF(t, c, pathIntegrations, enableForm(plainGELF))
	if stale.Code != http.StatusSeeOther || !strings.HasPrefix(stale.Header().Get("Location"), "/stepup") {
		t.Fatalf("stale step-up: %d %s", stale.Code, stale.Header().Get("Location"))
	}
}

// withCSRF adds the page's CSRF token and the current revision unless form sets it.
func withCSRF(t *testing.T, c *client, form url.Values) url.Values {
	t.Helper()
	body := c.get(pathIntegrations).Body.String()
	form.Set(csrfField, csrfForAny(t, body, pathIntegrations))
	if form.Get("rev") == "" {
		form.Set("rev", regexp.MustCompile(`name="rev" value="(\d+)"`).FindStringSubmatch(body)[1])
	}
	return form
}

func TestIntegrationsFileManagedAndLocked(t *testing.T) {
	t.Parallel()
	g := newGELFEnv(t, `audit: { gelf: { address: "`+plainGELF+`" } }`+"\n")
	c := g.adminClient()
	result(c.get(pathIntegrations)).status(t, http.StatusOK).contains(t, "Managed by config.yaml",
		"Set in config.yaml (audit.gelf.address)", `value="`+plainGELF+`" aria-describedby="i-gelf-address-hint i-gelf-address-src" disabled`)
	form := url.Values{"gelf.address": {"10.9.0.99:1"}}
	result(c.do(http.MethodPost, pathIntegrations, withCSRF(t, c, form))).status(t, http.StatusForbidden)

	l := newGELFEnv(t, "settings: { locked: [integrations] }\n")
	lc := l.adminClient()
	result(lc.get(pathIntegrations)).status(t, http.StatusOK).contains(t, "locked by <code>settings.locked</code>").
		lacks(t, "Save and apply", "Send test", "Fetch and confirm")
	result(postGELF(t, lc, pathGELFFetch, enableForm(tlsGELF))).status(t, http.StatusForbidden)
	if rec, ok := l.findAudit(integrations.ActionFingerprint, audit.ResultDenied); !ok || rec.ErrorClass != "locked" {
		t.Fatalf("locked fetch not audited: %+v", rec)
	}
}

func TestIntegrationsFetchAndConfirmPin(t *testing.T) {
	t.Parallel()
	g := newGELFEnv(t, "")
	c := g.adminClient()
	form := enableForm(tlsGELF)
	form.Set("gelf.server_name", "gelf.example.test") // the name the certificate carries
	page := postGELF(t, c, pathGELFFetch, form)
	r := result(page).status(t, http.StatusOK).contains(t, "Confirm the log server certificate", tlsGELF,
		"The CA that issued it (issuer)", "The log server&#39;s own certificate (leaf)", "CN=Test log CA",
		`id="pin-issuer" name="pinned" value="issuer" checked`)
	if page.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("confirm page is cacheable")
	}
	body := r.rec.Body.String()
	if rec, ok := g.findAudit(integrations.ActionFingerprint, audit.ResultOK); !ok || !strings.Contains(rec.ParamsJSON, `"port":6514`) {
		t.Fatalf("fetch not audited: %+v", rec)
	}
	confirm := hiddenFields(body)
	confirm.Set("pinned", "issuer")
	// A swapped value fails the proof.
	tampered := cloneValues(confirm)
	tampered.Set("value_issuer", g.pair.Leaf.SPKI())
	result(c.do(http.MethodPost, pathGELFPin, tampered)).status(t, http.StatusUnprocessableEntity).contains(t, "could not be confirmed")
	result(c.do(http.MethodPost, pathGELFPin, confirm)).status(t, http.StatusSeeOther).location(t, pathIntegrations+"?done=pinned")
	cur := g.set.Current().Integrations
	if cur.PinSHA256 != g.pair.CA.SPKI() || cur.Transport != config.TransportTLS || !cur.Enabled {
		t.Fatalf("saved %+v", cur)
	}
	if rec, ok := g.findAudit(settings.ActionIntegrationsPin, audit.ResultOK); !ok ||
		!strings.Contains(rec.ParamsJSON, `"pin_via":"fetched"`) || !strings.Contains(rec.ParamsJSON, `"pinned":"issuer"`) {
		t.Fatalf("pin row %+v", rec)
	}
	waitUntil(t, func() bool { return g.svc.Stats().TLS })
	result(c.get(pathIntegrations)).contains(t, "TLS, pinned", tofu.CertInfo{SPKI: g.pair.CA.SPKI()}.Grouped(), "Reset Certificate fingerprint (TLS) to default")
	result(c.do(http.MethodPost, pathGELFPin, url.Values{csrfField: {confirm.Get(csrfField)}, "pinned": {"both"}})).
		status(t, http.StatusUnprocessableEntity)
}

func TestIntegrationsFetchRefusals(t *testing.T) {
	t.Parallel()
	g := newGELFEnv(t, "")
	c := g.adminClient()
	result(postGELF(t, c, pathGELFFetch, url.Values{"gelf.address": {""}})).status(t, http.StatusUnprocessableEntity).
		contains(t, "Enter the log server")
	result(postGELF(t, c, pathGELFFetch, enableForm("127.0.0.1:6514"))).status(t, http.StatusUnprocessableEntity).
		contains(t, "Certificate not fetched")
	result(postGELF(t, c, pathGELFFetch, enableForm("10.9.0.99:6514"))).status(t, http.StatusUnprocessableEntity).
		contains(t, "Fingerprint not fetched")
	for range 4 {
		postGELF(t, c, pathGELFFetch, enableForm("10.9.0.99:6514"))
	}
	result(postGELF(t, c, pathGELFFetch, enableForm("10.9.0.99:6514"))).status(t, http.StatusTooManyRequests)
	if rec, ok := g.findAudit(integrations.ActionFingerprint, audit.ResultDenied); !ok || rec.ErrorClass != "rate_limited" {
		t.Fatalf("rate limit not audited %+v", rec)
	}
}

func TestIntegrationsManualPinAndReset(t *testing.T) {
	t.Parallel()
	g := newGELFEnv(t, "")
	c := g.adminClient()
	form := enableForm(tlsGELF)
	form.Set("gelf.transport", "tls")
	form.Set("gelf.pin_sha256", strings.ToUpper(g.pair.Leaf.SPKI()))
	result(postGELF(t, c, pathIntegrations, form)).status(t, http.StatusSeeOther)
	if rec, ok := g.findAudit(settings.ActionIntegrationsPin, audit.ResultOK); !ok || !strings.Contains(rec.ParamsJSON, `"pin_via":"manual"`) {
		t.Fatalf("manual pin %+v", rec)
	}
	result(postGELF(t, c, pathGELFReset, url.Values{"reset": {config.KeyGELFEnabled}})).
		status(t, http.StatusSeeOther).location(t, pathIntegrations+"?done=reset")
	if g.set.Current().Integrations.Enabled {
		t.Fatal("reset did not disable")
	}
	result(postGELF(t, c, pathGELFReset, url.Values{"reset": {config.KeyGELFEnabled}})).
		location(t, pathIntegrations+"?done=unchanged")
	result(postGELF(t, c, pathGELFReset, url.Values{"reset": {"gelf.bogus"}})).status(t, http.StatusUnprocessableEntity)
}

func TestIntegrationsWithoutBackend(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t)
	c := e.adminClient()
	result(c.get(pathIntegrations)).status(t, http.StatusNotFound)
	result(c.get("/")).lacks(t, "Audit shipping paused")
}

// pausedIntegrations is an Integrations whose shipper is paused on a pin mismatch.
type pausedIntegrations struct{ Integrations }

func (pausedIntegrations) Stats() audit.ShipperStats {
	return audit.ShipperStats{Active: true, PinMismatch: true}
}

func (pausedIntegrations) Note() string { return "The GELF settings saved here are not in force." }

func TestOverviewBannerWhenShippingPaused(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t, func(d *Deps) { d.Integrations = pausedIntegrations{} })
	c := e.adminClient()
	result(c.get("/")).status(t, http.StatusOK).contains(t, "Audit shipping paused:", `href="/settings/integrations">Check Settings`,
		"up to 1,024", "Audit shipping settings not in force:")
	viewer := e.signInViewer(t, "vic", "192.0.2.22")
	result(viewer.get("/")).contains(t, "Audit shipping paused:").lacks(t, `href="/settings/integrations">Check Settings`,
		"settings not in force")
}

func TestGELFStateAndMessages(t *testing.T) {
	t.Parallel()
	tf := timeFmt{loc: time.UTC}
	now := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	st := gelfState(audit.ShipperStats{Active: true, Connected: false, LastError: audit.ClassTimeout, LastSuccess: now},
		config.GELF{Address: plainGELF, Transport: "tcp"}, tf)
	if p := gelfState(audit.ShipperStats{Active: true, PinMismatch: true, PauseReason: audit.ClassTLSExpired, LastError: audit.ClassDial},
		config.GELF{Address: plainGELF, Transport: "tls"}, tf); p.Status.Label != "Paused: certificate expired" || !strings.Contains(p.ErrorMsg, "expired") {
		t.Fatalf("paused state %+v", p)
	}
	if st.Status.Label != "Disconnected" || !st.Plain || st.ErrorMsg == "" || len(st.Lines) != 7 {
		t.Fatalf("%+v", st)
	}
	for _, k := range []string{"saved", "reset", "unchanged", "pinned", "test-ok", "test-failed-tls_pin"} {
		if msg, _ := integrationsDone(k); msg == "" {
			t.Errorf("no message for %s", k)
		}
	}
	if gelfInvalidKey(errors.New("audit.gelf.server_name x")) != config.KeyGELFServerName ||
		gelfInvalidKey(errors.New("Ship audit rows must be on or off")) != config.KeyGELFEnabled || gelfInvalidKey(errors.New("x")) != "" {
		t.Fatal("invalid key")
	}
	if _, _, ok := splitHostPort("x:0"); ok {
		t.Fatal("port 0 accepted")
	}
	if prefixList(nil) == "" {
		t.Fatal("empty list text")
	}
}

func hiddenFields(body string) url.Values {
	out := url.Values{}
	for _, m := range regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`).FindAllStringSubmatch(body, -1) {
		out.Set(m[1], htmlUnescape(m[2]))
	}
	return out
}

func htmlUnescape(s string) string {
	return strings.NewReplacer("&#43;", "+", "&amp;", "&", "&#34;", `"`, "&#39;", "'", "&lt;", "<", "&gt;", ">").Replace(s)
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vals := range v {
		out[k] = append([]string(nil), vals...)
	}
	return out
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// postGELF posts form (nil: empty) to action with the page's CSRF token and revision.
func postGELF(t *testing.T, c *client, action string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	return c.do(http.MethodPost, action, withCSRF(t, c, cloneValues(form)))
}

// TestIntegrationsIssuerNeedsTheName: fetched by IP, the certificate (issued for a name)
// does not cover the address, so its CA is not offered and the leaf is preselected.
func TestIntegrationsIssuerNeedsTheName(t *testing.T) {
	t.Parallel()
	g := newGELFEnv(t, "")
	c := g.adminClient()
	result(postGELF(t, c, pathGELFFetch, enableForm(tlsGELF))).status(t, http.StatusOK).
		contains(t, "not issued for this address", `id="pin-leaf" name="pinned" value="leaf" checked`).
		lacks(t, `value="issuer"`)
}

// TestIntegrationsFormDetails: Reset buttons belong to their own form (Enter in a field
// submits Save), aria-invalid sits on the inputs, a down destination is warned about
// before Save, a confirm with shipping off says so, and saved values that no longer
// validate are reported.
func TestIntegrationsFormDetails(t *testing.T) {
	t.Parallel()
	g := newGELFEnv(t, "")
	c := g.adminClient()
	form := enableForm("10.9.0.99:12201") // allowed, but nothing answers there
	result(postGELF(t, c, pathIntegrations, form)).status(t, http.StatusSeeOther)
	postGELF(t, c, pathGELFTest, nil) // the dial fails: shipping is on but not connected
	waitUntil(t, func() bool { return g.svc.Stats().LastError != "" })
	r := result(c.get(pathIntegrations)).contains(t, `<form id="gelf-reset" method="post" action="/settings/integrations/reset" hidden>`,
		`form="gelf-reset" name="reset" value="gelf.enabled"`, "The current destination is not connected")
	r.lacks(t, `formaction="/settings/integrations/reset"`, `<fieldset aria-invalid`)
	bad := enableForm("10.9.0.99:12201")
	bad.Set("gelf.enabled", "maybe")
	result(postGELF(t, c, pathIntegrations, bad)).status(t, http.StatusUnprocessableEntity).
		contains(t, `name="gelf.enabled" value="on" aria-invalid="true"`)
	off := url.Values{"gelf.enabled": {"off"}, "gelf.address": {tlsGELF}, "gelf.server_name": {"gelf.example.test"}}
	result(postGELF(t, c, pathGELFFetch, off)).status(t, http.StatusOK).contains(t, "Shipping stays off until you turn it on.")
	result(c.get(pathIntegrations+"?done=test-failed-tls_expired")).contains(t, "has expired")
}

// noteSettings reports saved GELF values that are not in force.
type noteSettings struct{ Settings }

func (n noteSettings) Current() settings.Effective {
	e := n.Settings.Current()
	e.IntegrationsNote = "The GELF settings saved here are not in force (test)."
	return e
}

func TestIntegrationsNoteForDiscardedRows(t *testing.T) {
	t.Parallel()
	g := newGELFEnv(t, "", func(d *Deps) { d.Settings = noteSettings{d.Settings} })
	result(g.adminClient().get(pathIntegrations)).status(t, http.StatusOK).contains(t, "not in force (test)")
}

// expiredIntegrations is paused because the certificate expired.
type expiredIntegrations struct{ pausedIntegrations }

func (expiredIntegrations) Stats() audit.ShipperStats {
	return audit.ShipperStats{Active: true, PinMismatch: true, PauseReason: audit.ClassTLSExpired}
}

func TestOverviewBannerExpired(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t, func(d *Deps) { d.Integrations = expiredIntegrations{} })
	result(e.adminClient().get("/")).status(t, http.StatusOK).contains(t, "certificate has expired").
		lacks(t, "does not match the pinned fingerprint")
}

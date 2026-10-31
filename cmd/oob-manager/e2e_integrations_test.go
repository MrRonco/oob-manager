//go:build e2e

package main

import (
	"context"
	"html"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"oob-manager/internal/notify"
	"oob-manager/internal/store"
	"oob-manager/internal/tlspin/tlspintest"
)

var hiddenInput = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// hiddenOf collects a page's hidden inputs (the confirm page carries the form values,
// the two values and their proofs).
func hiddenOf(p page) url.Values {
	out := url.Values{}
	for _, m := range hiddenInput.FindAllStringSubmatch(p.body, -1) {
		out.Set(m[1], html.UnescapeString(m[2]))
	}
	return out
}

// gelfSave posts the Integrations form with the page's revision.
func gelfSave(t *testing.T, b browser, fields url.Values) page {
	t.Helper()
	p := b.get("/settings/integrations")
	form := url.Values{"csrf_token": {formCSRF(t, p, "/settings/integrations")}, "rev": {revOf(t, p)}}
	for k, v := range fields {
		form[k] = v
	}
	return b.post("/settings/integrations", form)
}

// checkIntegrations runs slice S4 in its own stack: plain TCP shipping set in the
// browser, a switch to TLS by fetch-and-confirm (the update row reaches the OLD input,
// the applied row the new one), Send test, a wrong pin that pauses shipping (Overview
// banner, trust webhook, /readyz degraded) and its repair; no token on the page.
func checkIntegrations(t *testing.T) {
	s := startStack(t, "127.0.0.1:0")
	b := browser{t: t, base: s.base, c: s.client(t)}
	login(t, b, s)
	first := b.get("/settings/integrations")
	expectPage(t, first, "Audit shipping (GELF)", "Disabled", "&lt;token&gt;", "/api/v1/servers/r730xd", "/readyz")
	if strings.Contains(first.body, s.token) || strings.Contains(first.body, "oobk_") {
		t.Fatal("a token reached the Integrations page")
	}

	expectRedirect(t, gelfSave(t, b, url.Values{"gelf.enabled": {"on"}, "gelf.address": {gelfPlainAddr},
		"gelf.transport": {"tcp"}}), "/settings/integrations?done=saved")
	waitFor(t, "applied row at the plain input", func() bool { return s.gelfPlain.has("admin.integrations.applied") })
	waitFor(t, "readyz ok while connected", func() bool { return strings.Contains(b.get("/readyz").body, `"ok"`) })

	// A managed BMC is never a GELF destination, nor the target of a certificate fetch.
	p0 := b.get("/settings/integrations")
	refused := b.post("/settings/integrations/gelf/fingerprint", url.Values{"csrf_token": {formCSRF(t, p0, "/settings/integrations")},
		"rev": {revOf(t, p0)}, "gelf.enabled": {"on"}, "gelf.address": {"192.0.2.10:443"}})
	if refused.status != 422 || !strings.Contains(refused.body, "address of a BMC") {
		t.Fatalf("fetch from a BMC: %d", refused.status)
	}

	// Fetch the TLS input's certificate and pin its issuer.
	p := b.get("/settings/integrations")
	fetch := b.post("/settings/integrations/gelf/fingerprint", url.Values{"csrf_token": {formCSRF(t, p, "/settings/integrations")},
		"rev": {revOf(t, p)}, "gelf.enabled": {"on"}, "gelf.address": {gelfTLSAddr}, "gelf.server_name": {gelfName}})
	expectPage(t, fetch, "Confirm the log server certificate", "The CA that issued it (issuer)")
	confirm := hiddenOf(fetch)
	confirm.Set("pinned", "issuer")
	expectRedirect(t, b.post("/settings/integrations/gelf/pin", confirm), "/settings/integrations?done=pinned")
	waitFor(t, "applied row at the TLS input", func() bool { return s.gelfTLS.has("admin.integrations.applied") })
	waitFor(t, "update row at the old input", func() bool { return s.gelfPlain.has("admin.integrations.update") })
	if s.gelfTLS.count("admin.integrations.update") != 0 {
		t.Fatal("the redirecting update row went to the new destination instead of the old one")
	}

	expectRedirect(t, b.submit("/settings/integrations", "/settings/integrations/gelf/test", url.Values{}),
		"/settings/integrations?done=test-ok")
	waitFor(t, "test frame", func() bool { return s.gelfTLS.has("oob-manager GELF test by admin") })

	checkGELFPinMismatch(t, b, s)
	if code := s.stop(); code != 0 {
		t.Fatalf("serve exit %d", code)
	}
	assertActions(t, s.dbPath, "admin.integrations.update", "admin.integrations.applied",
		"admin.integrations.gelf.fingerprint", "admin.integrations.gelf.pin", "admin.integrations.gelf.test")
}

// checkGELFPinMismatch pastes a wrong pin: the TLS handshake is refused, shipping
// pauses, Overview shows the banner, the trust webhook fires and /readyz is degraded.
// Pasting the issuer pin again repairs it and resolves the event.
func checkGELFPinMismatch(t *testing.T, b browser, s *stack) {
	t.Helper()
	wrong := tlspintest.SelfSigned(t).Leaf.SPKI()
	expectRedirect(t, gelfSave(t, b, url.Values{"gelf.pin_sha256": {wrong}}), "/settings/integrations?done=saved")
	b.submit("/settings/integrations", "/settings/integrations/gelf/test", url.Values{}) // makes the shipper dial now
	waitFor(t, "overview banner", func() bool { return strings.Contains(b.get("/").body, "Audit shipping paused") })
	waitFor(t, "readyz degraded", func() bool { return strings.Contains(b.get("/readyz").body, `"degraded"`) })
	waitFor(t, "trust webhook", func() bool { return s.hooks.has(notify.ClassTrust, "GELF server certificate mismatch") })
	expectPage(t, b.get("/settings/integrations"), "Paused: certificate changed")

	expectRedirect(t, gelfSave(t, b, url.Values{"gelf.pin_sha256": {s.gelfTLS.pair.CA.SPKI()}}), "/settings/integrations?done=saved")
	waitFor(t, "readyz ok again", func() bool { return strings.Contains(b.get("/readyz").body, `"ok"`) })
	waitFor(t, "trust resolved", func() bool { return s.hooks.has(notify.ClassTrust, "check passes again") })
	if strings.Contains(b.get("/").body, "Audit shipping paused") {
		t.Fatal("banner still shown after the repair")
	}
}

// assertActions checks that each action has at least one audit row (searched by action,
// so a long log cannot hide it).
func assertActions(t *testing.T, dbPath string, actions ...string) {
	t.Helper()
	db, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, a := range actions {
		rows, err := db.AuditSearch().Search(context.Background(), store.AuditFilter{Action: a, Limit: 1})
		if err != nil || len(rows) == 0 {
			t.Errorf("no audit row for %s (%v)", a, err)
		}
	}
}

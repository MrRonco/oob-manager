package ui

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/notify"
	"oob-manager/internal/secrets"
	"oob-manager/internal/web"
)

// pushRecv is a fake push service that records request bodies and answers with code.
type pushRecv struct {
	srv  *httptest.Server
	mu   sync.Mutex
	body []string
	code int
}

func newPushRecv(t *testing.T) *pushRecv {
	t.Helper()
	p := &pushRecv{code: http.StatusOK}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.body = append(p.body, string(b)+" "+r.Header.Get("Authorization"))
		code := p.code
		p.mu.Unlock()
		w.WriteHeader(code)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *pushRecv) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.body...)
}

type notifyEnv struct {
	*settingsEnv
	svc  *notify.Service
	recv *pushRecv
}

// newNotifyEnv is the Settings env with a real notify.Service over the same database.
func newNotifyEnv(t *testing.T, file ...notify.FileTarget) *notifyEnv {
	t.Helper()
	e := newSettingsEnv(t)
	recv := newPushRecv(t)
	pool := x509.NewCertPool()
	pool.AddCert(recv.srv.Certificate())
	sealer, err := notify.NewSealer(bytes.Repeat([]byte{9}, 32))
	must(t, err)
	svc, err := notify.New(context.Background(), notify.Config{DB: e.db, Sealer: sealer, File: file,
		Audit: audit.NewLogger(e.db.Audit(), nil, e.clock.Now, quiet()), Logger: quiet(), Now: e.clock.Now,
		WatchEvery: time.Hour, Dispatch: notify.DispatchConfig{Attempts: 1, Transport: notify.Transport{
			Policy: notify.Policy{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}},
			TLS:    &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}})
	must(t, err)
	e.deps.Notifications = svc
	app, err := New(e.deps)
	must(t, err)
	e.handler, err = web.NewHandler(app, web.Options{Logger: quiet()})
	must(t, err)
	return &notifyEnv{settingsEnv: e, svc: svc, recv: recv}
}

func (e *notifyEnv) signInAs(t *testing.T, name string, role authz.Role, ip string) *client {
	t.Helper()
	link, err := e.settingsEnv.svc.CreateUser(context.Background(), actorFor(t, e.settingsEnv, "morgan"), name, role)
	must(t, err)
	c := e.client(ip)
	c.login(name, e.enrolViaLink(link.Token, testPassword))
	return c
}

func ntfyForm(e *notifyEnv, id, token string) url.Values {
	return url.Values{"kind": {"ntfy"}, "id": {id}, "name": {"Phone " + id}, "url": {e.recv.srv.URL + "/topic-" + id},
		"token": {token}, "enabled": {"on"}, "min_severity": {"warning"}, "classes": {"health", "power", "console"}}
}

const uiSecret = "tk_UI-SECRET-VALUE" //nolint:gosec // G101: a fake secret the tests look for

func TestNotifyAddEditTestDelete(t *testing.T) {
	e := newNotifyEnv(t)
	c := e.adminClient()
	result(c.get("/settings/notifications")).status(t, http.StatusOK).contains(t, "No targets yet", "Add a target",
		`href="/settings/notifications" aria-current="page"`)
	result(c.get("/settings/notifications/new?kind=ntfy")).status(t, http.StatusOK).
		contains(t, "Add ntfy target", "Topic URL", `name="token" type="password"`, `id="c-health" name="classes" value="health" checked`)
	result(c.get("/settings/notifications/new?kind=bogus")).status(t, http.StatusSeeOther)

	rec := c.submit("/settings/notifications/new?kind=ntfy", "/settings/notifications", ntfyForm(e, "phone", uiSecret))
	result(rec).status(t, http.StatusSeeOther).location(t, "/settings/notifications?done=notify-created")
	list := c.get("/settings/notifications?done=notify-created")
	result(list).contains(t, "Target added.", "Phone phone", "127.0.0.1", "Secret set · v1",
		"health, power, console · warning and above", "Nothing sent yet").lacks(t, uiSecret, "topic-phone")

	edit := c.get("/settings/notifications/phone")
	result(edit).status(t, http.StatusOK).contains(t, "Edit Phone phone", "Remove the stored secrets").lacks(t, uiSecret)
	f := ntfyForm(e, "phone", "")
	f.Set("name", "Renamed")
	result(c.submit("/settings/notifications/phone", "/settings/notifications/phone", f)).
		status(t, http.StatusSeeOther).location(t, "/settings/notifications?done=notify-saved")
	if tv, _ := e.svc.Target("phone"); tv.Target.Name != "Renamed" || tv.Target.SecretVersion != 1 {
		t.Fatalf("after edit: %+v", tv.Target)
	}

	result(c.submit("/settings/notifications", "/settings/notifications/phone/test", nil)).
		status(t, http.StatusSeeOther).location(t, "/settings/notifications?done=notify-test")
	if got := e.recv.seen(); len(got) != 1 || !strings.Contains(got[0], "Bearer "+uiSecret) || !strings.Contains(got[0], "morgan") {
		t.Fatalf("test delivery: %v", got)
	}
	e.recv.mu.Lock()
	e.recv.code = http.StatusUnauthorized
	e.recv.mu.Unlock()
	result(c.submit("/settings/notifications", "/settings/notifications/phone/test", nil)).
		location(t, "/settings/notifications?done=notify-test-failed-http_4xx")
	result(c.get("/settings/notifications?done=notify-test-failed-http_4xx")).contains(t, "Test failed: the receiver refused it",
		"Last send failed", "(http_4xx)")
	result(c.submit("/settings/notifications", "/settings/notifications/phone/test", nil)).status(t, http.StatusSeeOther)
	result(c.submit("/settings/notifications", "/settings/notifications/phone/test", nil)).status(t, http.StatusTooManyRequests)

	confirm := c.get("/settings/notifications/phone/delete")
	result(confirm).status(t, http.StatusOK).contains(t, "Delete notification target Renamed?", "Cannot be undone")
	rec = c.do(http.MethodPost, "/settings/notifications/phone/delete", url.Values{
		csrfField: {csrfForAny(t, confirm.Body.String(), "/settings/notifications/phone/delete")}, "confirm": {"yes"}})
	result(rec).status(t, http.StatusSeeOther).location(t, "/settings/notifications?done=notify-deleted")
	if _, ok := e.svc.Target("phone"); ok {
		t.Fatal("target not deleted")
	}
	for _, a := range []string{notify.ActionTargetCreate, notify.ActionTargetUpdate, notify.ActionTargetTest, notify.ActionTargetDelete} {
		if _, ok := e.findAudit(a, audit.ResultOK); !ok {
			t.Errorf("no audit row %s", a)
		}
	}
	if e.auditContains(uiSecret) || e.auditContains("topic-phone") {
		t.Fatal("secret or URL path in the audit log")
	}
}

func TestNotifyInvalidInputKeepsSecretsOut(t *testing.T) {
	e := newNotifyEnv(t)
	c := e.adminClient()
	f := ntfyForm(e, "phone", uiSecret)
	f.Set("url", "http://example.net/plain")
	rec := c.submit("/settings/notifications/new?kind=ntfy", "/settings/notifications", f)
	result(rec).status(t, http.StatusUnprocessableEntity).contains(t, "Not saved:", "allow plaintext").lacks(t, uiSecret)
	f = ntfyForm(e, "phone", uiSecret)
	f["classes"] = []string{"bogus"}
	result(c.submit("/settings/notifications/new?kind=ntfy", "/settings/notifications", f)).status(t, http.StatusUnprocessableEntity)
	f = ntfyForm(e, "phone", uiSecret)
	f.Set("min_severity", "loud")
	result(c.submit("/settings/notifications/new?kind=ntfy", "/settings/notifications", f)).status(t, http.StatusUnprocessableEntity)
	f.Set("kind", "slack")
	result(c.submit("/settings/notifications/new?kind=ntfy", "/settings/notifications", f)).status(t, http.StatusBadRequest)
	result(c.submit("/settings/notifications/new?kind=ntfy", "/settings/notifications", ntfyForm(e, "a", ""))).status(t, http.StatusSeeOther)
	result(c.submit("/settings/notifications/new?kind=ntfy", "/settings/notifications", ntfyForm(e, "a", ""))).status(t, http.StatusConflict)
	result(c.get("/settings/notifications/nope")).status(t, http.StatusNotFound)
}

func TestNotifyEmailAndPushoverForms(t *testing.T) {
	e := newNotifyEnv(t)
	c := e.adminClient()
	result(c.get("/settings/notifications/new?kind=email")).contains(t, "SMTP server", `value="587"`, "STARTTLS (required)")
	mail := url.Values{"kind": {"email"}, "id": {"mail"}, "name": {"Mail"}, "smtp_host": {"192.0.2.25"}, "smtp_port": {"587"},
		"email_security": {"starttls"}, "email_from": {"oob@example.org"}, "email_to": {"a@example.org, b@example.org"},
		"user": {"mailer"}, "password": {"MAIL-PASS-SECRET"}, "enabled": {"on"}, "min_severity": {"critical"}, "classes": {"health"}}
	result(c.submit("/settings/notifications/new?kind=email", "/settings/notifications", mail)).status(t, http.StatusSeeOther)
	tv, _ := e.svc.Target("mail")
	if tv.Target.URL != "smtp://192.0.2.25:587" || len(tv.Target.EmailTo) != 2 || !tv.HasSecret {
		t.Fatalf("email target %+v", tv)
	}
	result(c.get("/settings/notifications/mail")).contains(t, `value="192.0.2.25"`, `value="a@example.org, b@example.org"`).
		lacks(t, "MAIL-PASS-SECRET", "mailer")
	result(c.get("/settings/notifications/new?kind=pushover")).contains(t, notify.DefaultPushoverURL, "Application token",
		"User key", "Critical as emergency priority")
	po := url.Values{"kind": {"pushover"}, "id": {"po"}, "name": {"PO"}, "url": {notify.DefaultPushoverURL},
		"enabled": {"on"}, "min_severity": {"warning"}, "classes": {"health"}}
	result(c.submit("/settings/notifications/new?kind=pushover", "/settings/notifications", po)).
		status(t, http.StatusUnprocessableEntity).contains(t, "Pushover needs an application token and a user key")
}

func TestNotifyFileTargetsLockedAndRoles(t *testing.T) {
	file := notify.Target{ID: "cfg", Name: "From file", Kind: notify.KindWebhook, URL: "https://hooks.example.net/x",
		Enabled: true, Classes: notify.Classes(), MinSeverity: notify.SeverityWarning}
	e := newNotifyEnv(t, notify.FileTarget{Target: file, Secrets: notify.Secrets{Token: secrets.New("FILE-HMAC")}})
	c := e.adminClient()
	result(c.get("/settings/notifications")).contains(t, "From file", "Managed by config.yaml", "Secret from the credential file").
		lacks(t, `href="/settings/notifications/cfg"`, "FILE-HMAC")
	result(c.get("/settings/notifications/cfg")).status(t, http.StatusForbidden)
	f := url.Values{"name": {"x"}, "url": {"https://hooks.example.net/y"}, "min_severity": {"info"}}
	f.Set(csrfField, e.csrfToken(c))
	result(c.do(http.MethodPost, "/settings/notifications/cfg", f)).status(t, http.StatusForbidden)
	result(c.get("/settings/notifications/cfg/delete")).status(t, http.StatusNotFound)

	op := e.signInAs(t, "oscar", authz.RoleOperator, "192.0.2.30")
	result(op.get("/settings/notifications")).status(t, http.StatusForbidden)
	csrf := e.csrfToken(op)
	rec := op.do(http.MethodPost, "/settings/notifications", url.Values{csrfField: {csrf}, "kind": {"ntfy"}})
	result(rec).status(t, http.StatusForbidden)
	if _, ok := e.findAudit(string(authz.AdminNotificationsManage), audit.ResultDenied); !ok {
		t.Fatal("refusal not audited")
	}
}

func TestNotifyStaleStepUpRedirects(t *testing.T) {
	e := newNotifyEnv(t)
	c := e.adminClient()
	page := c.get("/settings/notifications/new?kind=ntfy").Body.String()
	e.clock.Advance(10 * time.Minute)
	f := ntfyForm(e, "late", uiSecret)
	f.Set(csrfField, csrfForAny(t, page, "/settings/notifications"))
	rec := c.do(http.MethodPost, "/settings/notifications", f)
	resumeFrom(t, result(rec), "/settings/notifications")
	if _, ok := e.svc.Target("late"); ok {
		t.Fatal("created without a fresh step-up")
	}
}

func TestNotifyFailingBanner(t *testing.T) {
	e := newNotifyEnv(t)
	c := e.adminClient()
	viewer := e.signInAs(t, "vera", authz.RoleViewer, "192.0.2.31")
	// A failing target shows the banner on the Overview (linked for admins only).
	result(c.submit("/settings/notifications/new?kind=ntfy", "/settings/notifications", ntfyForm(e, "phone", ""))).status(t, http.StatusSeeOther)
	e.recv.mu.Lock()
	e.recv.code = http.StatusInternalServerError
	e.recv.mu.Unlock()
	for range 3 {
		_ = e.svc.SendTest(context.Background(), actorFor(t, e.settingsEnv, "morgan"), "phone")
	}
	result(c.get("/")).contains(t, "Notifications failing:", "Phone phone", `href="/settings/notifications"`)
	result(viewer.get("/")).contains(t, "Notifications failing:").lacks(t, "Check Settings → Notifications")
}

func TestNotifyPagesHiddenWithoutService(t *testing.T) {
	e := newSettingsEnv(t)
	c := e.adminClient()
	result(c.get("/settings/notifications")).status(t, http.StatusNotFound)
	result(c.get("/servers/r730xd")).lacks(t, "Mute notifications")
	result(c.get("/")).lacks(t, "Notifications failing")
}

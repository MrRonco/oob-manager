package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/store"
	"oob-manager/internal/store/authrepo"
	"oob-manager/internal/web"
)

// settingsEnv runs the UI over the real store, auth, audit and admin service, so the
// Settings tests exercise the same transactions as production.
type settingsEnv struct {
	*harness
	db     *store.DB
	svc    *admin.Service
	tokens *auth.TokenService
	secret string // the bootstrap admin's TOTP secret
}

func newSettingsEnv(t *testing.T, tweak ...func(*Deps)) *settingsEnv {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "ui.db"))
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	h := &harness{t: t, clock: &clock{t: time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)}, fleet: testFleet()}
	h.fleet.servers = fleetAt(h.clock.Now())
	h.hasher, err = auth.NewPasswordHasher(auth.Argon2Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, auth.MaxHashConcurrency)
	must(t, err)
	h.sealer, err = auth.NewAESGCMSealer([]byte(strings.Repeat("s", 32)))
	must(t, err)
	repos := authrepo.New(db)
	h.authn, err = auth.New(auth.Config{Users: repos.Users, Sessions: repos.Sessions, Lockouts: repos.Lockouts,
		Hasher: h.hasher, Sealer: h.sealer, Now: h.clock.Now, Logger: quiet()})
	must(t, err)
	tokens, err := auth.NewTokenService(repos.Tokens, h.clock.Now)
	must(t, err)
	lg := audit.NewLogger(db.Audit(), nil, h.clock.Now, quiet())
	svc, err := admin.New(admin.Config{DB: db, Audit: lg, Hasher: h.hasher, Sealer: h.sealer, Tokens: tokens,
		Now: h.clock.Now, Logger: quiet()})
	must(t, err)
	enr, err := h.authn.BootstrapAdmin(ctx, "morgan", testPassword)
	must(t, err)
	must(t, h.authn.ConfirmTOTP(ctx, "morgan", testPassword, h.code(enr.Secret), "192.0.2.1"))
	h.deps = Deps{Auth: h.authn, Fleet: h.fleet, Audit: lg, Admin: svc, AuditLog: audit.NewViewer(db.Audit(), db.AuditSearch()),
		Logger: quiet(), Now: h.clock.Now, CSRFKey: []byte(strings.Repeat("c", 32)), PublicURL: "https://oob.test",
		Build: Build{Version: "1.2.3", Commit: "abc1234", GoVersion: "go1.27.3",
			Modules:       []Module{{Path: "example.test/mod", Version: "v1.0.0"}},
			SchemaVersion: db.SchemaVersion}}
	for _, fn := range tweak {
		fn(&h.deps)
	}
	app, err := New(h.deps)
	must(t, err)
	h.handler, err = web.NewHandler(app, web.Options{Logger: quiet()})
	must(t, err)
	return &settingsEnv{harness: h, db: db, svc: svc, tokens: tokens, secret: enr.Secret}
}

// adminClient is morgan, signed in (so the step-up window is fresh for 5 minutes).
func (e *settingsEnv) adminClient() *client {
	c := e.client("192.0.2.10")
	c.login("morgan", e.secret)
	return c
}

// submit loads page, takes the CSRF token of the form posting to action, and posts
// that form with fields.
func (c *client) submit(page, action string, fields url.Values) *httptest.ResponseRecorder {
	c.h.t.Helper()
	body := c.get(page).Body.String()
	form := url.Values{csrfField: {csrfForAny(c.h.t, body, action)}}
	for k, v := range fields {
		form[k] = v
	}
	return c.do(http.MethodPost, action, form)
}

// csrfForAny finds the CSRF token of the form posting to action, wherever the hidden
// input sits inside it.
func csrfForAny(t *testing.T, body, action string) string {
	t.Helper()
	re := regexp.MustCompile(`(?s)action="` + regexp.QuoteMeta(action) + `"[^>]*>.*?name="csrf_token" value="([^"]+)"`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no form for %s in:\n%s", action, body)
	}
	return m[1]
}

// findAudit returns the newest row with action and result.
func (e *settingsEnv) findAudit(action, result string) (store.AuditRecord, bool) {
	rows, err := e.db.AuditSearch().Search(context.Background(), store.AuditFilter{Action: action, Result: result, Limit: 1})
	if err != nil || len(rows) == 0 {
		return store.AuditRecord{}, false
	}
	return rows[0], true
}

// auditContains reports whether any audit row contains s.
func (e *settingsEnv) auditContains(s string) bool {
	rows, err := e.db.Audit().List(context.Background(), 0, store.MaxAuditPage)
	must(e.t, err)
	for _, r := range rows {
		if strings.Contains(r.ParamsJSON+r.Principal+r.ErrorClass, s) {
			return true
		}
	}
	return false
}

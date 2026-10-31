package ui

import (
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
)

// appScript matches the optional enhancement scripts a page loads from 'self': app.js on every
// page, palette.js on signed-in pages (plan 04 §7).
var appScript = regexp.MustCompile(`<script src="/static/(?:app|palette)\.js\?v=[a-zA-Z0-9._-]*" defer></script>`)

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if sub != "" && strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// TestEveryPageIsCSPClean renders every page and checks for anything the strict CSP
// would block or that would leak a secret.
func TestEveryPageIsCSPClean(t *testing.T) {
	h := newHarness(t)
	secret := h.addUser("morgan", authz.RoleAdmin, true)
	anon := h.client("192.0.2.70")
	pages := map[string]string{
		"login": anon.get("/login").Body.String(), "enroll": anon.get("/enroll").Body.String(),
		"404": anon.get("/nope").Body.String(),
	}
	c := h.client("192.0.2.100")
	c.login("morgan", secret)
	token := c.jar[auth.SessionCookieName]
	for _, p := range []string{"/", "/servers/r730xd", "/servers/r240", "/servers/spare", "/servers/r730xd/events",
		"/servers/r730xd/inventory", "/servers/x/events"} {
		rec := c.get(p)
		pages[p] = rec.Body.String()
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'none'") {
			t.Errorf("%s: CSP header missing", p)
		}
	}
	forbidden := []string{"<script", " style=", "javascript:", " on" + "click=", testPassword, secret, token,
		strings.Repeat("c", 32), strings.Repeat("s", 32)}
	for name, body := range pages {
		// The one script every page may load: the optional enhancement from 'self'.
		body = appScript.ReplaceAllString(body, "")
		for _, f := range forbidden {
			if strings.Contains(body, f) {
				t.Errorf("page %s contains %q", name, f)
			}
		}
		if !strings.Contains(body, `<html lang="en"`) {
			t.Errorf("page %s lacks lang", name)
		}
	}
}

func TestFormsHaveLabels(t *testing.T) {
	h := newHarness(t)
	c := h.client("192.0.2.70")
	for _, p := range []string{"/login", "/enroll"} {
		body := c.get(p).Body.String()
		for _, id := range []string{"username", "password"} {
			if p == "/enroll" {
				id = "c-" + id
			}
			if !strings.Contains(body, `<label for="`+id+`"`) || !strings.Contains(body, `id="`+id+`"`) {
				t.Errorf("%s: input %s has no label", p, id)
			}
		}
	}
}

func TestCookiesAreHostPrefixedAndStrict(t *testing.T) {
	h := newHarness(t)
	rec := h.client("192.0.2.70").get("/login")
	cs := rec.Result().Cookies()
	if len(cs) != 1 || cs[0].Name != preCookieName || !cs[0].Secure || !cs[0].HttpOnly ||
		cs[0].SameSite != http.SameSiteStrictMode || cs[0].Path != "/" {
		t.Fatalf("pre-session cookie = %+v", cs)
	}
}

func TestNewValidates(t *testing.T) {
	h := newHarness(t)
	cases := map[string]func(*Deps){
		"no auth":   func(d *Deps) { d.Auth = nil },
		"no fleet":  func(d *Deps) { d.Fleet = nil },
		"no audit":  func(d *Deps) { d.Audit = nil },
		"short key": func(d *Deps) { d.CSRFKey = []byte("short") },
	}
	for name, fn := range cases {
		d := h.deps
		fn(&d)
		if _, err := New(d); err == nil {
			t.Errorf("%s: New accepted invalid deps", name)
		}
	}
	d := h.deps
	d.CSRFKey, d.Logger, d.Now, d.Authorize = nil, nil, nil, nil
	if _, err := New(d); err != nil {
		t.Fatalf("defaults rejected: %v", err)
	}
}

var cssURLRE = regexp.MustCompile(`url\(\s*["']?([^"')]*)`)

// TestStylesheetsStaySelfContained: under style-src/font-src/img-src 'self' the sheets
// may only reference the vendored fonts by relative URL; no imports, no other origin, no
// script-ish values (round-2 slice B grew the sheets, tech_doc §40).
func TestStylesheetsStaySelfContained(t *testing.T) {
	files, err := fs.Glob(staticFS, "static/*.css")
	if err != nil || len(files) < 4 {
		t.Fatalf("stylesheets: %v %v", files, err)
	}
	for _, f := range files {
		b, err := staticFS.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		css := cssCommentRE.ReplaceAllString(string(b), "")
		for _, bad := range []string{"@import", "http:", "https:", "//", "expression(", "javascript:", "behavior:", "-moz-binding"} {
			if strings.Contains(css, bad) {
				t.Errorf("%s contains %q", f, bad)
			}
		}
		for _, m := range cssURLRE.FindAllStringSubmatch(css, -1) {
			if !strings.HasPrefix(m[1], "vendor/fonts/") || strings.Contains(m[1], "..") {
				t.Errorf("%s references url(%s); only the vendored fonts are allowed", f, m[1])
			}
		}
	}
}

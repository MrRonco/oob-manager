package ui

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// The status favicons (round-2 slice B, plan 04 §11 item 11): a background tab shows the
// fleet's worst state; signed-out pages show the plain mark and no build fingerprint.

func TestFaviconFollowsTheWorstState(t *testing.T) {
	if got := (pillView{Class: "gp-unknown", Text: "No servers", Empty: true}).Favicon(); got != "" {
		t.Errorf("an empty fleet must keep the plain mark, got %q", got)
	}
	if got := pillOf(fleetCounts{}).Favicon(); got != "" {
		t.Errorf("pillOf(no servers) favicon = %q, want the plain mark", got)
	}
	for class, want := range map[string]string{"": "", "gp-crit": "crit", "gp-warn": "warn", "gp-stale": "stale",
		"gp-unknown": "stale", "gp-off": "off", "gp-ok": "ok", "gp-maint": "ok"} {
		if got := (pillView{Class: class}).Favicon(); got != want {
			t.Errorf("Favicon(%q) = %q, want %q", class, got, want)
		}
	}
	for c, want := range map[fleetCounts]string{
		{Total: 2, OK: 2}:                     "ok",
		{Total: 3, OK: 1, Warning: 1, Off: 1}: "warn",
		{Total: 2, Critical: 1, Stale: 1}:     "crit",
		{Total: 2, OK: 1, Off: 1}:             "off",
		{Total: 2, OK: 1, Maintenance: 1}:     "ok",
		{Total: 2, Stale: 1, OK: 1}:           "stale",
	} {
		if got := pillOf(c).Favicon(); got != want {
			t.Errorf("%+v: favicon %q, want %q", c, got, want)
		}
	}
}

func TestFaviconFilesAndLinks(t *testing.T) {
	h, c := signedIn(t, func(d *Deps) { d.Build = Build{Version: "1.2.3"} })
	result(c.get("/")).contains(t, `<link rel="icon" href="/static/favicon-stale.svg?v=1.2.3" type="image/svg+xml">`)
	result(h.client("192.0.2.41").get("/login")).contains(t, `<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">`).
		lacks(t, "favicon-", "1.2.3")
	for _, f := range []string{"favicon.svg", "logo.svg", "favicon-ok.svg", "favicon-warn.svg", "favicon-crit.svg",
		"favicon-stale.svg", "favicon-off.svg", "mark.svg"} {
		rec := c.get("/static/" + f)
		result(rec).status(t, http.StatusOK)
		body := rec.Body.String()
		if !strings.HasPrefix(body, "<svg") || containsAny(body, "<script", "style", " on", "href", "<foreignObject") {
			t.Errorf("%s is not a plain SVG: %.80s", f, body)
		}
		if rec.Header().Get("Cache-Control") != staticCacheControl {
			t.Errorf("%s Cache-Control = %q", f, rec.Header().Get("Cache-Control"))
		}
	}
}

// TestFaviconWithoutUserIsPlain: a page without a signed-in user never shows the fleet's
// state, even if a pill were filled in.
func TestFaviconWithoutUserIsPlain(t *testing.T) {
	d := layoutData{Pill: pillView{Class: "gp-crit", Text: "1 critical"}}
	if got := d.Favicon(); got != "" {
		t.Errorf("no user: favicon %q, want the plain mark", got)
	}
	if d.User = "alice"; d.Favicon() != "crit" {
		t.Errorf("signed in: favicon %q, want crit", d.Favicon())
	}
	h := newHarness(t)
	result(h.client("192.0.2.42").get("/login")).contains(t, `href="/static/favicon.svg"`).lacks(t, "favicon-")
}

var paintRE = regexp.MustCompile(`(fill|stroke)="#[0-9a-f]{6}"`)

// TestFaviconShapesDiffer: the five status favicons differ by the badge's shape, not
// only by its colour (greyscale and colour-vision safe), like the status icons.
func TestFaviconShapesDiffer(t *testing.T) {
	seen := map[string]string{}
	for _, s := range []string{"ok", "warn", "crit", "stale", "off"} {
		b, err := staticFS.ReadFile("static/favicon-" + s + ".svg")
		if err != nil {
			t.Fatal(err)
		}
		shape := paintRE.ReplaceAllString(string(b), "")
		if other, dup := seen[shape]; dup {
			t.Errorf("favicon-%s has the same shape as favicon-%s", s, other)
		}
		seen[shape] = s
	}
}

package ui

import (
	"io/fs"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

var (
	useHrefRE  = regexp.MustCompile(`<use href="#i-([^"]*)"`)
	symbolIDRE = regexp.MustCompile(`<symbol id="i-([^"]+)" viewBox="0 0 24 24">`)
	iconCallRE = regexp.MustCompile(`template "icon" "([^"]+)"`)
)

func spriteNames(t *testing.T) (string, []string) {
	t.Helper()
	sprite, names, err := buildSprite(iconFS, staticFS)
	if err != nil {
		t.Fatal(err)
	}
	return string(sprite), names
}

// TestSpriteHoldsTheVendoredIcons: one symbol per Lucide file plus the mark, about 40
// icons (plan 04 §11 item 10), and nothing but shapes.
func TestSpriteHoldsTheVendoredIcons(t *testing.T) {
	t.Parallel()
	sprite, names := spriteNames(t)
	files, err := fs.Glob(iconFS, lucideIconDir+"/*.svg")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != len(files)+1 || !slices.Contains(names, markName) {
		t.Fatalf("sprite has %d symbols for %d Lucide files + the mark: %v", len(names), len(files), names)
	}
	if n := len(names); n < 30 || n > 50 {
		t.Errorf("the sprite should hold about 40 icons, has %d", n)
	}
	var ids []string
	for _, m := range symbolIDRE.FindAllStringSubmatch(sprite, -1) {
		ids = append(ids, m[1])
	}
	if !slices.Equal(ids, names) {
		t.Errorf("symbol ids %v, names %v", ids, names)
	}
	if !strings.HasPrefix(sprite, `<svg class="sprite" width="0" height="0" aria-hidden="true" focusable="false">`) {
		t.Errorf("sprite root = %.100s", sprite)
	}
	for _, bad := range []string{"style", "script", "href", " on", "<use", "<g", "<!", "<?", "url("} {
		if strings.Contains(sprite, bad) {
			t.Errorf("sprite contains %q", bad)
		}
	}
}

// TestEveryPageIncludesTheSpriteAndResolvesItsIcons renders signed-in and signed-out
// pages: each carries the sprite exactly once and every <use> points at one of its symbols.
func TestEveryPageIncludesTheSpriteAndResolvesItsIcons(t *testing.T) {
	t.Parallel()
	_, names := spriteNames(t)
	h, c := signedIn(t)
	anon := h.client("192.0.2.40")
	pages := map[string]string{"login": anon.get("/login").Body.String(), "enroll": anon.get("/enroll").Body.String(),
		"help (signed out)": anon.get("/help").Body.String(), "404 (signed out)": anon.get("/nope").Body.String()}
	for _, p := range []string{"/", "/servers", "/servers/r730xd", "/servers/r240", "/servers/spare", "/servers/r730xd/events",
		"/servers/r730xd/inventory", "/servers/r730xd/sensors", "/servers/r730xd/activity", "/servers/r730xd/fan", "/activity", "/servers/r730xd/security", "/events", "/help",
		"/about", "/preferences", "/servers/nope"} {
		pages[p] = c.get(p).Body.String()
	}
	for name, body := range pages {
		if n := strings.Count(body, `<svg class="sprite"`); n != 1 {
			t.Errorf("%s: %d sprites, want 1", name, n)
		}
		uses := useHrefRE.FindAllStringSubmatch(body, -1)
		if len(uses) == 0 {
			t.Errorf("%s: no icon at all", name)
		}
		for _, m := range uses {
			if !slices.Contains(names, m[1]) {
				t.Errorf("%s: <use href=\"#i-%s\"> has no symbol", name, m[1])
			}
		}
	}
}

// goIconRE finds icon names chosen on the Go side (actionBtn.Icon, rendered with
// {{template "icon" .Icon}} in server.html).
var goIconRE = regexp.MustCompile(`\bIcon:\s*"([^"]+)"`)

// reservedIcons are vendored for slices C and D (menus, the command palette, header
// actions) and not drawn yet; a symbol that is neither used nor listed here fails.
var reservedIcons = []string{"copy", "plus", "rotate-ccw"}

// usedIcons returns every icon a template names literally or the Go code passes to one.
func usedIcons(t *testing.T) map[string]string {
	t.Helper()
	used := map[string]string{}
	scan := func(fsys fs.FS, pattern string, re *regexp.Regexp) {
		files, err := fs.Glob(fsys, pattern)
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: %v %v", pattern, files, err)
		}
		for _, f := range files {
			b, err := fs.ReadFile(fsys, f)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range re.FindAllStringSubmatch(string(b), -1) {
				used[m[1]] = f
			}
		}
	}
	scan(templateFS, "templates/*.html", iconCallRE)
	scan(os.DirFS("."), "*.go", goIconRE)
	return used
}

// TestTemplatesUseKnownIcons covers the icons of pages the render test above does not
// reach (settings, confirm and console pages) and the Go-chosen ones (fan, power,
// monitor): every icon named anywhere exists in the sprite.
func TestTemplatesUseKnownIcons(t *testing.T) {
	t.Parallel()
	_, names := spriteNames(t)
	used := usedIcons(t)
	if len(used) < 20 {
		t.Errorf("found only %d icons in use; the patterns are broken", len(used))
	}
	for icon, where := range used {
		if !slices.Contains(names, icon) {
			t.Errorf("%s: icon %q is not in the sprite", where, icon)
		}
	}
	for _, goIcon := range []string{"fan", "power", "monitor"} {
		if _, ok := used[goIcon]; !ok {
			t.Errorf("the Go-chosen icon %q was not found", goIcon)
		}
	}
}

// TestEverySpriteIconIsUsedOrReserved: no unexplained bytes in every page.
func TestEverySpriteIconIsUsedOrReserved(t *testing.T) {
	t.Parallel()
	_, names := spriteNames(t)
	used := usedIcons(t)
	for _, n := range names {
		_, inUse := used[n]
		reserved := slices.Contains(reservedIcons, n)
		switch {
		case inUse && reserved:
			t.Errorf("icon %q is used now; drop it from reservedIcons", n)
		case !inUse && !reserved:
			t.Errorf("icon %q is neither used nor reserved; remove it or reserve it", n)
		}
	}
	for _, r := range reservedIcons {
		if !slices.Contains(names, r) {
			t.Errorf("reserved icon %q is not in the sprite", r)
		}
	}
}

func TestIconShapesAllowList(t *testing.T) {
	t.Parallel()
	const head = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor">`
	ok, err := iconShapes([]byte(head + `<path d="M12 2v10"/><circle cx="1" cy="2" r="3" fill="currentColor" stroke="none"/>` +
		`<rect x="1" y="1" width="4" height="4" rx="1"/><line x1="0" y1="0" x2="1" y2="1"/><polyline points="1 2 3 4"/></svg>`))
	if err != nil || ok != `<path d="M12 2v10"/><circle cx="1" cy="2" r="3" fill="currentColor" stroke="none"/>`+
		`<rect x="1" y="1" width="4" height="4" rx="1"/><line x1="0" y1="0" x2="1" y2="1"/><polyline points="1 2 3 4"/>` {
		t.Fatalf("shapes = %q, %v", ok, err)
	}
	for name, body := range map[string]string{
		"script":         head + `<script>alert(1)</script></svg>`,
		"style attr":     head + `<path d="M1 1" style="fill:red"/></svg>`,
		"event handler":  head + `<path d="M1 1" onclick="x()"/></svg>`,
		"nested group":   head + `<g><path d="M1 1"/></g></svg>`,
		"use element":    head + `<use href="#x"/></svg>`,
		"xlink":          head + `<path xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="#x" d="M1 1"/></svg>`,
		"url in d":       head + `<path d="url(#x)"/></svg>`,
		"paint colour":   head + `<path d="M1 1" fill="red"/></svg>`,
		"text":           head + `hello</svg>`,
		"doctype":        `<!DOCTYPE svg>` + head + `<path d="M1 1"/></svg>`,
		"wrong grid":     `<svg viewBox="0 0 16 16"><path d="M1 1"/></svg>`,
		"not svg":        `<html><path d="M1 1"/></html>`,
		"no shapes":      head + `</svg>`,
		"malformed":      head + `<path d="M1 1">`,
		"too deep":       head + `<path d="M1 1"><path d="M2 2"/></path></svg>`,
		"proc. instr.":   `<?xml-stylesheet href="x.css"?>` + head + `<path d="M1 1"/></svg>`,
		"entity in attr": head + `<path d="M1 1&lt;"/></svg>`,
		"prefixed shape": head + `<x:path xmlns:x="urn:x" d="M1 1"/></svg>`,
		"undeclared ns":  head + `<x:path d="M1 1"/></svg>`,
		"foreign root":   `<x:svg xmlns:x="urn:x" viewBox="0 0 24 24"><path d="M1 1"/></x:svg>`,
	} {
		if _, err := iconShapes([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBuildSpriteErrors(t *testing.T) {
	t.Parallel()
	good := `<svg viewBox="0 0 24 24"><path d="M1 1"/></svg>`
	for name, fsys := range map[string]fstest.MapFS{
		"no icon dir": {markFile: {Data: []byte(good)}},
		"no mark":     {lucideIconDir + "/a.svg": {Data: []byte(good)}},
		"bad icon":    {markFile: {Data: []byte(good)}, lucideIconDir + "/a.svg": {Data: []byte(`<svg/>`)}},
		"bad name":    {markFile: {Data: []byte(good)}, lucideIconDir + "/A_b.svg": {Data: []byte(good)}},
	} {
		if _, _, err := buildSprite(fsys, fsys); err == nil {
			t.Errorf("%s: buildSprite succeeded", name)
		}
	}
	fsys := fstest.MapFS{markFile: {Data: []byte(good)},
		lucideIconDir + "/a.svg": {Data: []byte(good)}, lucideIconDir + "/README.md": {Data: []byte("x")}}
	sprite, names, err := buildSprite(fsys, fsys)
	if err != nil || !slices.Equal(names, []string{"a", "mark"}) || !strings.Contains(string(sprite), `<symbol id="i-a"`) {
		t.Fatalf("sprite = %q, %v, %v", sprite, names, err)
	}
}

func TestSpriteIsServedWithThePage(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t)
	result(c.get("/about")).contains(t, `<a href="/static/vendor/lucide-1.53.0/LICENSE">Lucide 1.53.0</a>`)
	result(c.get("/static/vendor/lucide-1.53.0/LICENSE")).status(t, http.StatusOK).contains(t, "ISC License")
	for _, p := range []string{"/static/vendor/lucide-1.53.0/icons/power.svg", "/static/iconsrc/lucide-1.53.0/icons/power.svg",
		"/static/lucide-1.53.0/icons/power.svg"} {
		result(c.get(p)).status(t, http.StatusNotFound) // the sources are built into the sprite, not served
	}
	rec := c.get("/")
	result(rec).status(t, http.StatusOK)
	body := rec.Body.String()
	if strings.Index(body, `<svg class="sprite"`) > strings.Index(body, `<a class="skip"`) {
		t.Error("the sprite must come first in <body>, before any <use>")
	}
}

// TestStatusIconsAreDistinct: every state class the "sicon" partial knows gets its own
// shape, so shape plus word carries the state (live is not drawn like stale).
func TestStatusIconsAreDistinct(t *testing.T) {
	t.Parallel()
	rd, err := newRenderer()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, class := range []string{"ok", "warn", "crit", "info", "pend", "stale", "live", "aging", "maint", "off", "unknown"} {
		var b strings.Builder
		if err := rd.pages[pageHelp].ExecuteTemplate(&b, "sicon", class); err != nil {
			t.Fatal(err)
		}
		m := useHrefRE.FindStringSubmatch(b.String())
		if m == nil {
			t.Fatalf("sicon %s rendered no icon: %q", class, b.String())
		}
		if other, dup := seen[m[1]]; dup {
			t.Errorf("sicon %s and %s both draw %s", class, other, m[1])
		}
		seen[m[1]] = class
	}
	for alias, want := range map[string]string{"good": "circle-check", "near": "triangle-alert"} {
		var b strings.Builder
		_ = rd.pages[pageHelp].ExecuteTemplate(&b, "sicon", alias)
		if !strings.Contains(b.String(), "#i-"+want) {
			t.Errorf("sicon %s = %q, want %s", alias, b.String(), want)
		}
	}
}

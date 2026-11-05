package ui

import (
	"path"
	"regexp"
	"strings"
	"testing"
)

// TestTokensDeclareVendoredFonts: every @font-face url points at a vendored file, uses
// font-display: swap, and each family has a metric-matched local fallback face.
func TestTokensDeclareVendoredFonts(t *testing.T) {
	t.Parallel()
	css, err := staticFS.ReadFile("static/tokens.css")
	if err != nil {
		t.Fatal(err)
	}
	faces := regexp.MustCompile(`(?s)@font-face \{(.*?)\}`).FindAllStringSubmatch(string(css), -1)
	urls := regexp.MustCompile(`url\("([^"]+)"\)`)
	seen := map[string]bool{}
	for _, f := range faces {
		for _, u := range urls.FindAllStringSubmatch(f[1], -1) {
			if _, err := staticFS.ReadFile("static/" + u[1]); err != nil {
				t.Errorf("@font-face url %s: %v", u[1], err)
			}
			if !strings.Contains(f[1], "font-display: swap") {
				t.Errorf("@font-face %s lacks font-display: swap", u[1])
			}
			seen[path.Base(path.Dir(u[1]))] = true
		}
	}
	for family := range vendoredFonts {
		if !seen[family] {
			t.Errorf("tokens.css has no @font-face for %s", family)
		}
	}
	stacks := map[string]string{}
	for _, r := range regexp.MustCompile(`--(font-ui|font-mono):\s*([^;]+);`).FindAllStringSubmatch(string(css), -1) {
		stacks[r[1]] = r[2]
	}
	for stack, faces := range map[string][2]string{"font-ui": {`"Inter"`, `"Inter Fallback"`},
		"font-mono": {`"JetBrains Mono"`, `"JetBrains Mono Fallback"`}} {
		if !strings.Contains(string(css), "font-family: "+faces[1]) {
			t.Errorf("tokens.css lacks the fallback face %s", faces[1])
		}
		if !strings.HasPrefix(stacks[stack], faces[0]+", "+faces[1]+", ") {
			t.Errorf("--%s = %q: want %s, then %s, then system fonts", stack, stacks[stack], faces[0], faces[1])
		}
	}
	if n := strings.Count(string(css), "size-adjust:"); n != len(vendoredFonts) {
		t.Errorf("%d metric-matched fallbacks, want %d", n, len(vendoredFonts))
	}
}

// TestPagesLoadTokensAndPreloadFonts: signed in and signed out, the page preloads both
// fonts without a build fingerprint and loads tokens.css before the other sheets.
func TestPagesLoadTokensAndPreloadFonts(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	secret := h.addUser("fontcheck", "viewer", true)
	signed := h.client("192.0.2.11")
	signed.login("fontcheck", secret)
	for name, body := range map[string]string{
		"login": h.client("192.0.2.12").get("/login").Body.String(), "overview": signed.get("/").Body.String()} {
		for family, file := range vendoredFonts {
			want := `<link rel="preload" href="/static/vendor/fonts/` + family + "/" + file + `" as="font" type="font/woff2" crossorigin>`
			if !strings.Contains(body, want) {
				t.Errorf("%s: no font preload for %s", name, family)
			}
		}
		tok, th, app, sh := strings.Index(body, "/static/tokens.css"), strings.Index(body, "/static/themes.css"),
			strings.Index(body, "/static/app.css"), strings.Index(body, "/static/shell.css")
		pg := strings.Index(body, "/static/pages.css")
		if tok < 0 || tok >= th || th >= app || app >= sh || sh >= pg {
			t.Errorf("%s: stylesheet order tokens %d, themes %d, app %d, shell %d, pages %d", name, tok, th, app, sh, pg)
		}
	}
}

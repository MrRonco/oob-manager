package ui

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
	"testing"
)

// The vendored fonts (tech_doc §2, §35): Inter and JetBrains Mono, SIL OFL 1.1, one
// variable woff2 per family under static/vendor/fonts/<family>-<version>/ next to its
// licence text.
var vendoredFonts = map[string]string{
	"inter-4.1":            "inter-var-latin.woff2",
	"jetbrains-mono-2.304": "jetbrains-mono-var-latin.woff2",
}

const (
	fontFamilyBudget = 120 << 10 // bytes of woff2 per family
	fontTotalBudget  = 250 << 10 // bytes of woff2 for all families
	fontsDir         = "static/vendor/fonts"
)

// TestVendoredFontsWithinBudget: exactly the chosen families, each with its OFL text,
// inside the size budget (plan 04 §6).
func TestVendoredFontsWithinBudget(t *testing.T) {
	t.Parallel()
	sizes, total := map[string]int64{}, int64(0)
	err := fs.WalkDir(staticFS, fontsDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path.Ext(p) != ".woff2" {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		family := path.Base(path.Dir(p))
		sizes[family] += info.Size()
		total += info.Size()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sizes) != len(vendoredFonts) {
		t.Errorf("font families on disk %v, want %v", sizes, vendoredFonts)
	}
	for family, file := range vendoredFonts {
		if sizes[family] == 0 || sizes[family] > fontFamilyBudget {
			t.Errorf("%s: %d bytes of woff2, budget 1..%d", family, sizes[family], fontFamilyBudget)
		}
		if _, err := staticFS.ReadFile(path.Join(fontsDir, family, file)); err != nil {
			t.Errorf("%s: %v", family, err)
		}
		ofl, err := staticFS.ReadFile(path.Join(fontsDir, family, "OFL.txt"))
		if err != nil || !strings.Contains(string(ofl), "SIL Open Font License, Version 1.1") {
			t.Errorf("%s: OFL.txt missing or not the OFL 1.1 text (%v)", family, err)
		}
	}
	if total > fontTotalBudget {
		t.Errorf("fonts total %d bytes, budget %d", total, fontTotalBudget)
	}
}

// TestFontsAreServedImmutable: the font URL carries its version in the path, so it is
// cached for a year; everything else keeps the one-hour cache.
func TestFontsAreServedImmutable(t *testing.T) {
	t.Parallel()
	c := newHarness(t).client("192.0.2.10")
	for family, file := range vendoredFonts {
		rec := c.get("/static/vendor/fonts/" + family + "/" + file)
		result(rec).status(t, http.StatusOK)
		if ct := rec.Header().Get("Content-Type"); ct != "font/woff2" {
			t.Errorf("%s: Content-Type %q", family, ct)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != fontCacheControl {
			t.Errorf("%s: Cache-Control %q", family, cc)
		}
	}
	if cc := c.get("/static/app.css").Header().Get("Cache-Control"); cc != staticCacheControl {
		t.Errorf("app.css Cache-Control %q", cc)
	}
	if cc := c.get("/static/vendor/fonts/inter-4.1/OFL.txt").Header().Get("Cache-Control"); cc != staticCacheControl {
		t.Errorf("OFL.txt Cache-Control %q (only woff2 is immutable)", cc)
	}
}

// TestAboutCreditsTheFonts: the About page names both fonts and links their OFL texts.
func TestAboutCreditsTheFonts(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t)
	result(c.get("/about")).status(t, http.StatusOK).contains(t,
		`<a href="/static/vendor/fonts/inter-4.1/OFL.txt">Inter 4.1</a>`,
		`<a href="/static/vendor/fonts/jetbrains-mono-2.304/OFL.txt">JetBrains Mono 2.304</a>`,
		"SIL Open Font License 1.1")
}

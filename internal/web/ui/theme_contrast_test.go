package ui

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
	"testing"

	"oob-manager/internal/display"
)

// themeTokens are the semantic tokens every palette must resolve in both modes.
var themeTokens = []string{"bg", "surface", "surface-2", "surface-3", "border", "field-border", "text", "muted",
	"accent", "accent-bg", "on-accent", "focus", "ok", "ok-bg", "ok-mark", "warn", "warn-bg", "warn-mark", "crit",
	"crit-bg", "crit-mark", "info", "info-bg", "info-mark", "stale-fg", "stale-bg", "stale-mark", "off", "off-bg",
	"off-fill", "on-off", "danger", "danger-hover", "on-danger", "btn-bg", "btn-bg-hover", "btn-fg"}

// statusFamilies maps each status to its ink token (text) and the prefix of its -bg
// (tinted background) and -mark (glyphs, outlines, meter fills) tokens.
var statusFamilies = [][2]string{{"ok", "ok"}, {"warn", "warn"}, {"crit", "crit"}, {"info", "info"},
	{"stale-fg", "stale"}, {"off", "off"}}

const semanticSelector = `:root, [data-palette]`

var (
	cssCommentRE = regexp.MustCompile(`(?s)/\*.*?\*/`)
	cssRuleRE    = regexp.MustCompile(`([^{}]+)\{([^{}]*)\}`)
	cssDeclRE    = regexp.MustCompile(`--([a-z0-9-]+)\s*:\s*([^;]+);`)
	cssVarRE     = regexp.MustCompile(`^var\(--([a-z0-9-]+)\)$`)
	paletteSelRE = regexp.MustCompile(`\[data-palette="([a-z-]+)"\]`)
)

// cssRule is one flat rule: its selector and its custom-property declarations.
type cssRule struct {
	selector string
	decls    map[string]string
}

func parseRules(t *testing.T, file string) []cssRule {
	t.Helper()
	b, err := staticFS.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var out []cssRule
	for _, m := range cssRuleRE.FindAllStringSubmatch(cssCommentRE.ReplaceAllString(string(b), ""), -1) {
		decls := map[string]string{}
		for _, d := range cssDeclRE.FindAllStringSubmatch(m[2], -1) {
			decls[d[1]] = strings.TrimSpace(d[2])
		}
		out = append(out, cssRule{selector: strings.TrimSpace(m[1]), decls: decls})
	}
	return out
}

// semanticLayer is the one block in tokens.css that maps semantic names to primitives.
func semanticLayer(t *testing.T) map[string]string {
	t.Helper()
	for _, r := range parseRules(t, "static/tokens.css") {
		if r.selector == semanticSelector {
			return r.decls
		}
	}
	t.Fatalf("tokens.css has no %q block", semanticSelector)
	return nil
}

// palettes reads themes.css into palette id → primitive declarations.
func palettes(t *testing.T) map[string]map[string]string {
	t.Helper()
	out := map[string]map[string]string{}
	for _, r := range parseRules(t, "static/themes.css") {
		m := paletteSelRE.FindStringSubmatch(r.selector)
		if m == nil {
			continue
		}
		if _, dup := out[m[1]]; dup {
			t.Errorf("palette %s is defined twice", m[1])
		}
		out[m[1]] = r.decls
	}
	return out
}

// resolve follows var() chains from a semantic token through the palette's primitives
// to a colour, picks the mode's side of light-dark(), and returns the painted hex.
func resolve(name string, sem, pal map[string]string, mode string) (string, error) {
	v, ok := sem[name]
	if !ok {
		return "", fmt.Errorf("--%s is not in the semantic layer", name)
	}
	for depth := 0; ; depth++ {
		m := cssVarRE.FindStringSubmatch(v)
		if m == nil {
			break
		}
		if depth > 8 {
			return "", fmt.Errorf("--%s: var() chain too deep", name)
		}
		if v, ok = pal[m[1]]; !ok {
			return "", fmt.Errorf("--%s: the palette does not define --%s", name, m[1])
		}
	}
	light, dark, err := splitLightDark(v)
	if err != nil {
		return "", err
	}
	pick := map[string]string{"light": light, "dark": dark}[mode]
	c, err := parseColor(pick)
	if err != nil {
		return "", fmt.Errorf("--%s: %w", name, err)
	}
	if !c.inGamut() {
		return "", fmt.Errorf("--%s: %s is outside the sRGB gamut", name, pick)
	}
	return c.hex(), nil
}

// resolvedThemes is palette → mode → semantic token → painted hex.
func resolvedThemes(t *testing.T) map[string]map[string]map[string]string {
	t.Helper()
	sem, pals := semanticLayer(t), palettes(t)
	out := map[string]map[string]map[string]string{}
	for id, pal := range pals {
		out[id] = map[string]map[string]string{}
		for _, mode := range []string{"dark", "light"} {
			out[id][mode] = map[string]string{}
			for _, name := range themeTokens {
				hex, err := resolve(name, sem, pal, mode)
				if err != nil {
					t.Errorf("%s %s: %v", id, mode, err)
					continue
				}
				out[id][mode][name] = hex
			}
		}
	}
	return out
}

func contrast(a, b string) float64 {
	ca, _ := parseColor(a)
	cb, _ := parseColor(b)
	la, lb := relLumRGB(ca), relLumRGB(cb)
	return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)
}

// themeProblems checks every token pair the CSS uses (round-2 slice B, tech_doc §40):
// body text, muted text, links and every status ink on every surface and tinted
// background; status marks, field borders and the focus ring at 3:1; the inks on solid
// fills (accent, critical, powered off, the neutral primary button); a focus ring that
// cannot be mistaken for the warning colour; and warning and critical marks that differ
// in lightness as well as hue (readable in greyscale).
func themeProblems(name string, tk map[string]string, textMin float64) []string {
	var bad []string
	need := func(a, b string, minRatio float64) {
		if len(tk[a]) != 7 || len(tk[b]) != 7 {
			bad = append(bad, fmt.Sprintf("%s: --%s or --%s is not a #rrggbb color", name, a, b))
			return
		}
		if r := contrast(tk[a], tk[b]); r < minRatio {
			bad = append(bad, fmt.Sprintf("%s: --%s on --%s is %.2f:1, need %.1f:1", name, a, b, r, minRatio))
		}
	}
	for _, bg := range []string{"bg", "surface", "surface-2", "surface-3"} {
		need("text", bg, textMin)
		need("muted", bg, textMin)
		need("accent", bg, 4.5)
		need("field-border", bg, 3)
		need("focus", bg, 3)
		for _, f := range statusFamilies {
			need(f[0], bg, 4.5)
			if f[1] != "off" {
				need(f[1]+"-mark", bg, 3)
			}
		}
	}
	for _, f := range statusFamilies {
		need(f[0], f[1]+"-bg", textMin)
		if f[1] != "off" {
			need(f[1]+"-mark", f[1]+"-bg", 3)
		}
		for _, other := range []string{"text", "muted", "accent"} {
			need(other, f[1]+"-bg", 4.5)
		}
	}
	for _, other := range []string{"text", "muted", "accent"} {
		need(other, "accent-bg", 4.5)
	}
	need("on-accent", "accent", 4.5)
	need("on-danger", "danger", 4.5)
	need("on-danger", "danger-hover", 4.5)
	need("on-off", "off-fill", 4.5)
	need("btn-fg", "btn-bg", 7)
	need("btn-fg", "btn-bg-hover", 7)
	need("danger", "surface", 3)
	return append(bad, focusAndLightness(name, tk)...)
}

// focusAndLightness: the focus ring stays distinct from the warning colour, and the
// warning mark differs in OKLab lightness by at least 0.12 from the critical fill and
// 0.1 from the critical mark (warning and critical icons and fills stay apart in greyscale).
func focusAndLightness(name string, tk map[string]string) []string {
	var bad []string
	for _, w := range []string{"warn", "warn-mark"} {
		if len(tk["focus"]) != 7 || len(tk[w]) != 7 {
			return append(bad, fmt.Sprintf("%s: --focus or --%s is missing", name, w))
		}
		if r := contrast(tk["focus"], tk[w]); r < 1.5 || strings.EqualFold(tk["focus"], tk[w]) {
			bad = append(bad, fmt.Sprintf("%s: the focus ring is too close to --%s (%.2f:1)", name, w, r))
		}
	}
	for _, pair := range []struct {
		other string
		min   float64
	}{{"danger", 0.12}, {"crit-mark", 0.1}} {
		if d := math.Abs(oklabL(tk["warn-mark"]) - oklabL(tk[pair.other])); d < pair.min {
			bad = append(bad, fmt.Sprintf("%s: --warn-mark and --%s differ by %.3f in lightness, need %.2f", name, pair.other, d, pair.min))
		}
	}
	return bad
}

// oklabL is the OKLab lightness of a #rrggbb colour.
func oklabL(hex string) float64 {
	c, _ := parseColor(hex)
	lin := func(v float64) float64 {
		if v <= 0.04045 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	r, g, b := lin(c[0]), lin(c[1]), lin(c[2])
	l := math.Cbrt(float64(0.4122214708*r) + float64(0.5363325363*g) + float64(0.0514459929*b))
	m := math.Cbrt(float64(0.2119034982*r) + float64(0.6806995451*g) + float64(0.1073969566*b))
	s := math.Cbrt(float64(0.0883024619*r) + float64(0.2817188376*g) + float64(0.6299787005*b))
	return float64(0.2104542553*l) + float64(0.7936177850*m) - float64(0.0040720468*s)
}

func TestThemeContrast(t *testing.T) {
	t.Parallel()
	themes := resolvedThemes(t)
	for _, th := range display.Themes() {
		id := string(th.ID)
		textMin := 4.5
		if th.ID == display.ThemeHighContrast {
			textMin = 7 // AAA-leaning
		}
		for _, mode := range []string{"dark", "light"} {
			tk, ok := themes[id][mode]
			if !ok {
				t.Errorf("themes.css has no %s palette", id)
				break
			}
			for _, p := range themeProblems(id+" "+mode, tk, textMin) {
				t.Error(p)
			}
		}
	}
	if len(themes) != len(display.Themes()) {
		t.Errorf("themes.css has %d palettes, display.Themes has %d", len(themes), len(display.Themes()))
	}
	if palettes(t)["high-contrast"]["focus-w"] != "4px" {
		t.Error("High contrast must thicken the focus ring (--focus-w: 4px)")
	}
}

const themeGolden = "testdata/theme-hex.txt"

// TestPalettesMatchGolden holds every palette, mode and semantic token to the 8-bit
// colour in testdata/theme-hex.txt, which themes.spec.ts also reads to check what
// Chromium actually paints. After regenerating themes.css: go test -run
// TestPalettesMatchGolden -update ./internal/web/ui/
//
// With -update this test rewrites the golden from the same CSS, so it cannot fail on its
// own; the chain is held by three checks: tools/themegen's TestThemesCSSIsGenerated
// (themes.css equals the generator's output; it runs in CI's test job, so no separate
// regenerate-and-diff step is needed), this test without -update (the committed golden
// equals what themes.css and tokens.css resolve to), and themes.spec.ts (Chromium paints
// the golden).
func TestPalettesMatchGolden(t *testing.T) {
	t.Parallel()
	themes := resolvedThemes(t)
	if *updateGolden {
		writeThemeGolden(t, themes)
	}
	golden := themeHexGolden(t)
	for key, want := range golden {
		if got := themes[key[0]][key[1]][key[2]]; got != want {
			t.Errorf("%s %s --%s = %s, golden %s", key[0], key[1], key[2], got, want)
		}
	}
	if want := len(display.Themes()) * 2 * len(themeTokens); len(golden) != want {
		t.Errorf("golden file has %d values, want %d", len(golden), want)
	}
}

func writeThemeGolden(t *testing.T, themes map[string]map[string]map[string]string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("# palette mode token hex: what every semantic token paints (generated by\n" +
		"# go test -run TestPalettesMatchGolden -update ./internal/web/ui/; read by tests/e2e/themes.spec.ts)\n")
	for _, th := range display.Themes() {
		for _, mode := range []string{"dark", "light"} {
			for _, name := range themeTokens {
				fmt.Fprintf(&b, "%s %s %s %s\n", th.ID, mode, name, themes[string(th.ID)][mode][name])
			}
		}
	}
	if err := os.WriteFile(themeGolden, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// themeHexGolden reads the golden file into {palette, mode, token} → hex.
func themeHexGolden(t *testing.T) map[[3]string]string {
	t.Helper()
	f, err := os.Open(themeGolden)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[[3]string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var id, mode, tok, hex string
		if _, err := fmt.Sscan(line, &id, &mode, &tok, &hex); err != nil {
			t.Fatalf("bad golden line %q", line)
		}
		out[[3]string{id, mode, tok}] = hex
	}
	return out
}

var fallbackRE = regexp.MustCompile(`@supports not \(color: light-dark\(#000, #fff\)\) \{\s*:root, \[data-palette\] \{([^}]*)\}\s*\}`)

// TestLightDarkFallback: a browser without light-dark() gets every semantic token as
// plain Graphite dark (the palettes' values would all be invalid there).
func TestLightDarkFallback(t *testing.T) {
	t.Parallel()
	css, err := staticFS.ReadFile("static/tokens.css")
	if err != nil {
		t.Fatal(err)
	}
	m := fallbackRE.FindStringSubmatch(cssCommentRE.ReplaceAllString(string(css), ""))
	if m == nil {
		t.Fatal("tokens.css has no @supports not (color: light-dark(#000, #fff)) fallback for :root, [data-palette]")
	}
	decls := map[string]string{}
	for _, d := range cssDeclRE.FindAllStringSubmatch(m[1], -1) {
		decls[d[1]] = strings.TrimSpace(d[2])
	}
	golden := themeHexGolden(t)
	for _, name := range themeTokens {
		if want := golden[[3]string{"graphite", "dark", name}]; decls[name] != want {
			t.Errorf("fallback --%s = %q, Graphite dark is %s", name, decls[name], want)
		}
	}
	if sem := semanticLayer(t); sem["bg"] != "var(--p-neutral-0)" {
		t.Errorf("the fallback must come after the semantic layer (first block --bg = %q)", sem["bg"])
	}
}

// TestTokenLayers keeps the two layers apart: palettes override primitives only, the
// semantic layer is written once (no colour arithmetic the Go check cannot evaluate),
// app.css, shell.css and pages.css define no colour token of their own, and Graphite is also the default.
func TestTokenLayers(t *testing.T) {
	t.Parallel()
	for _, r := range parseRules(t, "static/themes.css") {
		for name := range r.decls {
			if !strings.HasPrefix(name, "p-") && name != "focus-w" {
				t.Errorf("themes.css %s defines --%s; palettes may only override --p-* primitives", r.selector, name)
			}
		}
	}
	for name, v := range semanticLayer(t) {
		if strings.Contains(v, "color-mix(") || strings.Contains(v, " from ") {
			t.Errorf("semantic --%s uses colour arithmetic (%s)", name, v)
		}
	}
	for _, sheet := range []string{"app.css", "shell.css", "pages.css"} {
		for _, r := range parseRules(t, "static/"+sheet) {
			for _, name := range themeTokens {
				if _, ok := r.decls[name]; ok {
					t.Errorf("%s %s redefines --%s; colours live in tokens.css/themes.css", sheet, r.selector, name)
				}
			}
		}
	}
	css, err := staticFS.ReadFile("static/themes.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(css), `:root, [data-palette="graphite"] {`) {
		t.Error("Graphite must also be the default palette (:root)")
	}
}

func TestColorMath(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"oklch(100% 0 0)": "#ffffff", "oklch(0% 0 0)": "#000000",
		"oklch(62.8% 0.2577 29.23)": "#ff0000", "oklch(0.628 0.2577 29.23)": "#ff0000", "#4fd0e0": "#4fd0e0",
		"oklch(79.33% 0.1132 206.72)": "#4fd0e0"} {
		c, err := parseColor(in)
		if err != nil || c.hex() != want || !c.inGamut() {
			t.Errorf("%s = %s (in gamut %v, err %v), want %s", in, c.hex(), c.inGamut(), err, want)
		}
	}
	if c, _ := parseColor("oklch(70% 0.4 30)"); c.inGamut() {
		t.Error("oklch(70% 0.4 30) is outside sRGB and must be reported")
	}
	for _, bad := range []string{"red", "rgb(1 2 3)", "oklch(120% 0 0)", "oklch(50% 0.1 400)", "#abc",
		"oklch(1.2.3% 0 0)", "oklch(50% 0.1.1 20)", "oklch(50% 0.1 2..0)"} {
		if _, err := parseColor(bad); err == nil {
			t.Errorf("parseColor(%q) accepted", bad)
		}
	}
	if l, d, err := splitLightDark("light-dark(oklch(1 0 0), oklch(0 0 0))"); err != nil || l != "oklch(1 0 0)" || d != "oklch(0 0 0)" {
		t.Errorf("splitLightDark = %q, %q, %v", l, d, err)
	}
	if _, _, err := splitLightDark("light-dark(oklch(1 0 0))"); err == nil {
		t.Error("a one-argument light-dark() was accepted")
	}
	if r := contrast("#000000", "#ffffff"); math.Abs(r-21) > 0.01 {
		t.Fatalf("black/white = %.2f", r)
	}
	if r := contrast("#777777", "#ffffff"); math.Abs(r-4.48) > 0.01 {
		t.Fatalf("#777/white = %.2f", r)
	}
	if bad := themeProblems("x", map[string]string{"text": "#777777", "bg": "#ffffff"}, 4.5); len(bad) == 0 {
		t.Fatal("a failing pair was not reported")
	}
}

func TestResolveErrors(t *testing.T) {
	t.Parallel()
	sem := map[string]string{"bg": "var(--p-a)", "loop": "var(--p-loop)", "raw": "#000000", "bad": "var(--p-bad)"}
	pal := map[string]string{"p-a": "light-dark(#ffffff, #000000)", "p-loop": "var(--p-loop)",
		"p-bad": "oklch(70% 0.4 30)"}
	if hex, err := resolve("bg", sem, pal, "light"); err != nil || hex != "#ffffff" {
		t.Errorf("bg light = %s, %v", hex, err)
	}
	if hex, err := resolve("raw", sem, pal, "dark"); err != nil || hex != "#000000" {
		t.Errorf("raw = %s, %v", hex, err)
	}
	for _, name := range []string{"missing", "loop", "bad"} {
		if _, err := resolve(name, sem, pal, "dark"); err == nil {
			t.Errorf("resolve(%s) succeeded", name)
		}
	}
	if _, err := resolve("bg", sem, map[string]string{}, "dark"); err == nil {
		t.Error("a primitive missing from the palette was not reported")
	}
}

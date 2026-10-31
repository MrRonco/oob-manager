package main

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
)

// The six palettes as generated primitives (round-2 redesign slice B, docs/tech_doc.md
// §40). Each palette is a few inputs (neutral hue and chroma, accent hue, status hues);
// every ink is then fitted (lightness stepped towards more contrast) until it meets its
// WCAG ratio against every surface it is drawn on. Ported from the round-2 mockup
// generator (palettes.mjs, direction A "Quiet signal"), with the app's own primitive
// steps and the extra pairs the app's CSS uses.

type hues struct{ ok, warn, crit, info, stale float64 }

// base is a neutral ramp's hue and chroma.
type base struct{ h, c float64 }

type spec struct {
	id, label  string
	dark, lite base
	accent     float64
	hues       hues
	hc         bool // High contrast: black/white surfaces, 7:1 text, heavy borders
}

// anchors are the maintainer's status hues (plan 04 §11 item 2): OK 158, warning 78,
// critical 24, info 245, stale 98; the accent is cyan-teal 198.
var anchors = hues{ok: 158, warn: 78, crit: 24, info: 245, stale: 98}

const accentAnchor = 198

var graphite = base{250, 0.01}

var specs = []spec{
	{id: "graphite", label: "Graphite", dark: graphite, lite: graphite, accent: accentAnchor, hues: anchors},
	{id: "high-contrast", label: "High contrast", dark: base{250, 0}, lite: base{250, 0}, accent: 192,
		hues: hues{ok: 150, warn: 88, crit: 22, info: 245, stale: 98}, hc: true},
	{id: "solarized", label: "Solarized", dark: base{212, 0.042}, lite: base{92, 0.035}, accent: 185,
		hues: hues{ok: 125, warn: 88, crit: 28, info: 248, stale: 98}},
	{id: "nord", label: "Nord", dark: base{258, 0.03}, lite: base{258, 0.03}, accent: 200,
		hues: hues{ok: 135, warn: 85, crit: 18, info: 262, stale: 98}},
	{id: "dracula", label: "Dracula", dark: base{285, 0.034}, lite: base{88, 0.03}, accent: 300,
		hues: hues{ok: 150, warn: 62, crit: 20, info: 215, stale: 105}},
	{id: "colorblind", label: "Color-blind safe", dark: graphite, lite: graphite, accent: 170,
		hues: hues{ok: 238, warn: 98, crit: 42, info: 335, stale: 78}},
}

// surfaces: canvas, panel, field, raised (menus, meter tracks).
type surfaces struct{ bg, s1, s2, s3 float64 }

func surfacesFor(sp spec, dark bool) surfaces {
	switch {
	case sp.hc && dark:
		return surfaces{0, 0.05, 0.13, 0.2}
	case sp.hc:
		return surfaces{1, 1, 0.955, 0.9}
	case dark:
		return surfaces{0.165, 0.205, 0.245, 0.285}
	default:
		return surfaces{0.962, 1, 0.976, 0.95}
	}
}

// status is a family's starting point: the mark (glyphs, outlines, meter fills) and
// its chroma; the ink (text) is fitted from a fixed lightness.
type status struct {
	name    string
	hue     float64
	markL   float64
	markC   float64
	tintC   float64
	inkMaxC float64
}

func statuses(sp spec, dark bool) []status {
	pick := func(d, l float64) float64 {
		if dark {
			return d
		}
		return l
	}
	// The critical mark sits clearly below the warning mark in lightness (>= 0.1), so the
	// two read apart in greyscale; High contrast light needs a darker start for that.
	critLight := 0.5
	if sp.hc {
		critLight = 0.36
	}
	return []status{
		{"ok", sp.hues.ok, pick(0.8, 0.52), 0.14, 0.045, 0.13},
		{"warn", sp.hues.warn, pick(0.82, 0.64), 0.15, 0.045, 0.13},
		{"crit", sp.hues.crit, pick(0.7, critLight), 0.19, 0.045, 0.13},
		{"info", sp.hues.info, pick(0.77, 0.5), 0.1, 0.045, 0.1},
		{"stale", sp.hues.stale, pick(0.8, 0.52), 0.06, 0.025, 0.06},
	}
}

// palette is one mode's primitives, in output order.
type palette struct {
	names []string
	vals  map[string]lch
}

func (p *palette) set(name string, c lch) {
	p.names = append(p.names, name)
	p.vals[name] = c
}

// gen holds one palette and mode while its primitives are derived.
type gen struct {
	sp                  spec
	dark                bool
	b                   base
	sl                  surfaces
	dir                 float64 // towards more contrast against the surfaces
	p                   palette
	surf                []lch
	tints               map[string]lch
	accentTint, offTint lch
	err                 error // the first failure; later steps still run but makePalette reports it
}

func (g *gen) fail(err error) {
	if err != nil && g.err == nil {
		g.err = err
	}
}

// set writes a primitive (rounded as written) and returns the written colour.
func (g *gen) set(name string, c lch) lch {
	w := g.written(c)
	g.p.set(name, w)
	return w
}

func (g *gen) written(c lch) lch {
	w, err := c.written()
	g.fail(err)
	return w
}

func (g *gen) fit(c lch, dir float64, needs ...need) lch {
	w, err := fit(c, dir, needs...)
	if err != nil {
		g.fail(fmt.Errorf("%s %s: %w", g.sp.id, map[bool]string{true: "dark", false: "light"}[g.dark], err))
	}
	return w
}

func (g *gen) pick(d, l float64) float64 {
	if g.dark {
		return d
	}
	return l
}

func (g *gen) hcPick(hc, normal float64) float64 {
	if g.sp.hc {
		return hc
	}
	return normal
}

func (g *gen) n(l, k float64) lch { return lch{l, g.b.c * k, g.b.h} }

// makePalette derives every primitive of one palette in one mode.
func makePalette(sp spec, dark bool) (palette, error) {
	g := &gen{sp: sp, dark: dark, b: sp.lite, sl: surfacesFor(sp, dark), dir: -1, p: palette{vals: map[string]lch{}}}
	if dark {
		g.b, g.dir = sp.dark, 1
	}
	g.surfacesAndTints()
	g.neutrals()
	g.accent()
	g.statusRamps()
	g.fills()
	return g.p, g.err
}

func (g *gen) surfacesAndTints() {
	g.surf = []lch{g.set("p-neutral-0", g.n(g.sl.bg, 0.9)), g.set("p-neutral-1", g.n(g.sl.s1, 1)),
		g.set("p-neutral-2", g.n(g.sl.s2, 1)), g.set("p-neutral-4", g.n(g.sl.s3, 1.1))}
	tintL := g.pick(g.sl.s1+0.05, g.sl.s1-0.045)
	if g.sp.hc {
		tintL = g.pick(0.12, 0.93)
	}
	g.tints = map[string]lch{}
	for _, st := range statuses(g.sp, g.dark) {
		g.tints[st.name] = g.written(lch{tintL, g.hcPick(0.05, st.tintC), st.hue})
	}
	g.accentTint = g.written(lch{g.pick(g.sl.s1+0.055, g.sl.s1-0.05), 0.05, g.sp.accent})
	g.offTint = g.written(lch{tintL, 0.02, g.b.h})
}

// allTints are every tinted background text may sit on.
func (g *gen) allTints() []lch {
	out := []lch{g.accentTint, g.offTint}
	for _, st := range statuses(g.sp, g.dark) {
		out = append(out, g.tints[st.name])
	}
	return out
}

func (g *gen) neutrals() {
	text := g.set("p-neutral-9", g.fit(g.n(g.pick(g.hcPick(1, 0.955), g.hcPick(0, 0.2)), 0.5), g.dir,
		need{g.surf, g.hcPick(15, 12)}, need{g.allTints(), g.hcPick(9, 7)}))
	g.set("p-neutral-8", g.fit(g.n(g.pick(g.hcPick(0.92, 0.78), g.hcPick(0.18, 0.42)), 0.8), g.dir,
		need{g.surf, g.hcPick(10, 5.4)}, need{g.allTints(), g.hcPick(7, 4.6)}))
	lineStrong := g.set("p-neutral-6", g.fit(g.n(g.pick(0.64, 0.56), 0.8), g.dir, need{g.surf, g.hcPick(7, 3.3)}))
	if g.sp.hc {
		g.set("p-neutral-3", lineStrong)
	} else {
		g.set("p-neutral-3", g.n(g.sl.s1+float64(0.11*(text.L-g.sl.s1)), 1))
	}
	g.set("p-neutral-10", lch{g.pick(0.985, 0.08), 0, 0})
	// Primary button hover: the text ink moved 12 % towards the canvas, kept at 7:1.
	hover := lch{text.L + float64((g.surf[0].L-text.L)*0.12), text.C, text.H}
	g.set("p-neutral-7", g.fit(hover, g.dir, need{[]lch{g.surf[1]}, 7}))
}

func (g *gen) accent() {
	everywhere := append(append([]lch{}, g.surf...), g.allTints()...)
	accent := g.set("p-accent-7", g.fit(lch{g.pick(g.hcPick(0.88, 0.8), g.hcPick(0.35, 0.5)), g.hcPick(0.13, 0.125),
		g.sp.accent}, g.dir, need{everywhere, g.hcPick(8, 4.8)}))
	g.set("p-accent-1", g.accentTint)
	g.set("p-accent-0", g.fit(lch{g.pick(0.15, 1), 0.02, g.sp.accent}, -g.dir, need{[]lch{accent}, g.hcPick(6, 5.2)}))
}

// statusRamps: per status the tint (-1), the mark (-5, 3:1) and the ink (-7, text).
func (g *gen) statusRamps() {
	for _, st := range statuses(g.sp, g.dark) {
		tint := g.set("p-"+st.name+"-1", g.tints[st.name])
		on := append(append([]lch{}, g.surf...), tint)
		g.set("p-"+st.name+"-5", g.fit(lch{st.markL, g.hcPick(st.markC+0.03, st.markC), st.hue}, g.dir,
			need{on, g.hcPick(4.8, 3.2)}))
		g.set("p-"+st.name+"-7", g.fit(lch{g.pick(0.84, 0.4), math.Min(st.markC, st.inkMaxC), st.hue}, g.dir,
			need{on, g.hcPick(8, 5)}))
	}
}

// fills: the solid critical fill and the slate "off" family, each with its ink.
func (g *gen) fills() {
	critFill := g.set("p-crit-8", lch{g.pick(0.66, g.hcPick(0.33, 0.47)), g.hcPick(0.22, 0.2), g.sp.hues.crit})
	onCrit := lch{1, 0, 0}
	if g.dark {
		onCrit = lch{0.14, 0.02, g.sp.hues.crit}
	}
	on := g.set("p-crit-0", g.fit(onCrit, -g.dir, need{[]lch{critFill}, g.hcPick(6, 5.2)}))
	// Danger hover: the fill 0.05 further from its ink (lighter in dark, darker in light).
	g.set("p-crit-9", g.fit(lch{critFill.L + float64(g.dir*0.05), critFill.C, critFill.H}, g.dir,
		need{[]lch{on}, g.hcPick(6, 5.2)}))
	offFill := g.set("p-off-8", lch{g.pick(0.47, 0.42), 0.022, g.b.h})
	g.set("p-off-0", g.fit(lch{g.pick(0.98, 1), 0, 0}, 1, need{[]lch{offFill}, g.hcPick(6, 5.2)}))
	g.set("p-off-1", g.offTint)
	g.set("p-off-7", g.fit(lch{g.pick(0.76, 0.46), 0.03, g.b.h}, g.dir,
		need{append(append([]lch{}, g.surf...), g.offTint), g.hcPick(7, 4.8)}))
}

// written rounds the colour the way css() writes it, so every fit measures exactly
// what the stylesheet will say. It then nudges L by the written precision (0.01 %)
// until no channel sits near an 8-bit rounding boundary, so a browser's own conversion
// (float32, another matrix rounding) paints the same 8-bit colour as this generator
// computes (themes.spec.ts compares them exactly). No clear value within ±1 % of L is
// an error, never a silent fallback.
func (c lch) written() (lch, error) {
	g := c.gamutMap()
	base := lch{round(g.L*100, 2) / 100, floor4(g.C), round(math.Mod(math.Mod(g.H, 360)+360, 360), 1)}
	if base.C < 0.0005 {
		base.C, base.H = 0, 0
	}
	for i := range 200 {
		d := float64((i+1)/2) * 0.0001
		if i%2 == 1 {
			d = -d
		}
		cand := lch{math.Min(1, math.Max(0, round(base.L+d, 4))), base.C, base.H}
		if cand.inGamut() && clearOfRounding(cand) {
			return cand, nil
		}
	}
	return lch{}, fmt.Errorf("%s: every nearby lightness rounds ambiguously to 8 bits", base.css())
}

// clearOfRounding: every encoded channel is at least 0.1 of an 8-bit step away from a
// rounding boundary.
func clearOfRounding(c lch) bool {
	for _, v := range c.linear() {
		e := gammaEncode(v) * 255
		if f := e - math.Floor(e); f > 0.4 && f < 0.6 {
			return false
		}
	}
	return true
}

const header = `/* oob-manager palettes: GENERATED by ` + "`go run ./tools/themegen`" + ` (docs/tech_doc.md §40).
   Do not edit by hand; change the inputs in tools/themegen/palettes.go and regenerate
   (TestThemesCSSIsGenerated fails when this file and the generator disagree).
   <html data-palette="…"> is rendered by the server from the user's preference (or the
   app default), so there is no flash of the wrong theme and no JavaScript. Each palette
   is one block of --p-* primitives in OKLCH; light-dark(light, dark) carries both modes
   and follows color-scheme (tokens.css). The semantic names (--bg, --text, --ok …) are
   mapped onto these primitives once, in tokens.css; the same selectors match any element
   with data-palette, which is how the Display page previews each theme.
   Steps: neutral-0 canvas, -1 surface, -2 field, -3 hairline border, -4 raised surface,
   -6 field border, -8 muted text, -9 text, -10 focus ring; per family -1 tinted
   background, -5 mark (glyphs, outlines, meter fills, >= 3:1), -7 ink (text, >= 4.5:1),
   -8 solid fill, -0 the ink on a filled step. The comment after each line is the 8-bit
   colour it paints, light then dark. Every pair is checked by TestThemeContrast.
   Graphite comes first: it is also the default (:root) and later palettes override it. */
`

// render writes every palette block.
func render() (string, error) {
	var b strings.Builder
	b.WriteString(header)
	for _, sp := range specs {
		lite, err := makePalette(sp, false)
		if err != nil {
			return "", err
		}
		dark, err := makePalette(sp, true)
		if err != nil {
			return "", err
		}
		sel := `[data-palette="` + sp.id + `"]`
		if sp.id == "graphite" {
			sel = `:root, ` + sel
		}
		fmt.Fprintf(&b, "\n/* %s */\n%s {\n", sp.label, sel)
		for _, name := range ordered(lite.names) {
			l, d := lite.vals[name], dark.vals[name]
			fmt.Fprintf(&b, "  --%s: light-dark(%s, %s); /* %s %s */\n", name, l.css(), d.css(), l.hex(), d.hex())
		}
		if sp.hc {
			b.WriteString("  --focus-w: 4px;\n")
		}
		b.WriteString("}\n")
	}
	return b.String(), nil
}

var families = []string{"neutral", "accent", "ok", "warn", "crit", "info", "stale", "off"}

// ordered sorts primitive names by family, then by step.
func ordered(names []string) []string {
	key := func(name string) (int, int) {
		i := strings.LastIndex(name, "-")
		step, _ := strconv.Atoi(name[i+1:])
		return slices.Index(families, strings.TrimPrefix(name[:i], "p-")), step
	}
	out := slices.Clone(names)
	slices.SortFunc(out, func(a, b string) int {
		fa, sa := key(a)
		fb, sb := key(b)
		if fa != fb {
			return fa - fb
		}
		return sa - sb
	})
	return out
}

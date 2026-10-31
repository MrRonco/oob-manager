package ui

import (
	"math"
	"strconv"
	"testing"
)

// The round-2 colour anchors (plan 04 §11 item 2, tech_doc §40): status hues OK 158,
// warning 78, critical 24, info 245, stale 98; a cyan-teal accent at 198; a slate "off"
// tone; and in every palette the accent at least 40° from every status hue, so a link
// or a selection is never read as a state.

var statusHueFamilies = []string{"ok", "warn", "crit", "info", "stale"}

// declared returns the OKLCH chroma and hue a palette primitive is written with, per mode.
func declared(t *testing.T, pal map[string]string, name, mode string) (chroma, hue float64) {
	t.Helper()
	v, ok := pal[name]
	if !ok {
		t.Fatalf("--%s is not defined", name)
	}
	light, dark, err := splitLightDark(v)
	if err != nil {
		t.Fatal(err)
	}
	m := oklchRE.FindStringSubmatch(map[string]string{"light": light, "dark": dark}[mode])
	if m == nil {
		t.Fatalf("--%s %s is not oklch(): %s", name, mode, v)
	}
	chroma, _ = strconv.ParseFloat(m[3], 64)
	hue, _ = strconv.ParseFloat(m[4], 64)
	return chroma, hue
}

func hueDistance(a, b float64) float64 {
	d := math.Mod(math.Abs(a-b), 360)
	return math.Min(d, 360-d)
}

// Graphite's accent (198) and OK (158) are the maintainer's anchors and exactly 40° apart, the
// rule's minimum; every other palette keeps a small margin (42°) so a later tweak of its
// hues cannot slide onto the limit unnoticed.
func TestAccentStaysFarFromStatusHues(t *testing.T) {
	for id, pal := range palettes(t) {
		minGap := 42.0
		if id == "graphite" {
			minGap = 40 // the anchors themselves (plan 04 §11 item 2)
		}
		for _, mode := range []string{"dark", "light"} {
			_, accent := declared(t, pal, "p-accent-7", mode)
			for _, fam := range statusHueFamilies {
				for _, step := range []string{"1", "5", "7"} {
					name := "p-" + fam + "-" + step
					c, h := declared(t, pal, name, mode)
					if c == 0 {
						t.Errorf("%s %s --%s has no hue", id, mode, name)
					}
					if d := hueDistance(accent, h); d < minGap {
						t.Errorf("%s %s: accent hue %.1f is %.1f° from --%s (%.1f), need %.0f°", id, mode, accent, d, name, h, minGap)
					}
				}
			}
		}
	}
}

func TestGraphiteUsesTheAnchors(t *testing.T) {
	pal := palettes(t)["graphite"]
	want := map[string]float64{"accent": 198, "ok": 158, "warn": 78, "crit": 24, "info": 245, "stale": 98}
	steps := map[string][]string{"accent": {"1", "7"}, "crit": {"1", "5", "7", "8"}}
	for fam, hue := range want {
		for _, step := range stepsOr(steps[fam]) {
			for _, mode := range []string{"dark", "light"} {
				if _, h := declared(t, pal, "p-"+fam+"-"+step, mode); math.Abs(h-hue) > 0.05 {
					t.Errorf("graphite %s --p-%s-%s hue %.1f, anchor %.0f", mode, fam, step, h, hue)
				}
			}
		}
	}
	// Off is a slate: the neutral hue with a little chroma, never a status hue.
	for _, mode := range []string{"dark", "light"} {
		_, neutral := declared(t, pal, "p-neutral-1", "dark")
		for _, step := range []string{"1", "7", "8"} {
			c, h := declared(t, pal, "p-off-"+step, mode)
			if c > 0.03 || c == 0 || math.Abs(h-neutral) > 0.05 {
				t.Errorf("graphite %s --p-off-%s = chroma %.4f hue %.1f; want a slate (hue %.0f, chroma <= 0.03)", mode, step, c, h, neutral)
			}
		}
	}
}

func stepsOr(s []string) []string {
	if s == nil {
		return []string{"1", "5", "7"}
	}
	return s
}

func TestHueDistance(t *testing.T) {
	for _, tc := range [][3]float64{{10, 350, 20}, {198, 158, 40}, {0, 180, 180}, {720, 0, 0}} {
		if got := hueDistance(tc[0], tc[1]); got != tc[2] {
			t.Errorf("hueDistance(%v, %v) = %v", tc[0], tc[1], got)
		}
	}
}

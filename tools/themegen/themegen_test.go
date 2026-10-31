package main

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const themesCSS = "../../internal/web/ui/static/themes.css"

// TestThemesCSSIsGenerated: the committed stylesheet is exactly the generator's output,
// so nobody edits a colour by hand and the inputs stay the single source.
func TestThemesCSSIsGenerated(t *testing.T) {
	got, err := os.ReadFile(themesCSS)
	if err != nil {
		t.Fatal(err)
	}
	want, err := render()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatal("themes.css differs from the generator; run: go run ./tools/themegen -o internal/web/ui/static/themes.css")
	}
}

func TestColorMath(t *testing.T) {
	for _, tc := range []struct {
		c   lch
		hex string
	}{{lch{1, 0, 0}, "#ffffff"}, {lch{0, 0, 0}, "#000000"}, {lch{0.628, 0.2577, 29.23}, "#ff0000"},
		{lch{0.7933, 0.1132, 206.72}, "#4fd0e0"}, {lch{0.5, 0.4, 30}, "#bb0c00"}} {
		if got := tc.c.hex(); got != tc.hex {
			t.Errorf("%v = %s, want %s", tc.c, got, tc.hex)
		}
	}
	if (lch{0.7, 0.4, 30}).inGamut() || !(lch{0.7, 0.4, 30}).gamutMap().inGamut() {
		t.Error("gamut mapping")
	}
	if r := contrast(lch{0, 0, 0}, lch{1, 0, 0}); math.Abs(r-21) > 0.01 {
		t.Errorf("black/white = %.2f", r)
	}
	if got := (lch{0.5, 0.0001, 10}).css(); got != "oklch(50% 0 0)" {
		t.Errorf("near grey = %s", got)
	}
	if got := (lch{0.623456, 0.123456, -10}).css(); got != "oklch(62.35% 0.1234 350)" {
		t.Errorf("css = %s", got)
	}
	if c, err := fit(lch{0.5, 0, 0}, 1, need{[]lch{{0, 0, 0}}, 30}); err == nil { // 21:1 is the maximum
		t.Errorf("an unreachable fit must fail, got %v", c)
	}
	c, err := fit(lch{0.3, 0, 0}, 1, need{[]lch{{0, 0, 0}}, 7})
	if err != nil || contrast(c, lch{0, 0, 0}) < 7 {
		t.Errorf("fit = %v (%.2f:1), %v", c, contrast(c, lch{0, 0, 0}), err)
	}
	if w, err := c.written(); err != nil || w != c {
		t.Errorf("a fitted colour is already as written: %v -> %v, %v", c, w, err)
	}
	if got := floor4(0.12); got != 0.12 {
		t.Errorf("floor4(0.12) = %v", got)
	}
}

func TestWrite(t *testing.T) {
	var buf bytes.Buffer
	if err := write("", &buf); err != nil || !strings.HasPrefix(buf.String(), "/* oob-manager palettes") {
		t.Fatalf("stdout: %v %.40q", err, buf.String())
	}
	p := filepath.Join(t.TempDir(), "themes.css")
	if err := write(p, nil); err != nil {
		t.Fatal(err)
	}
	want, _ := render()
	if b, _ := os.ReadFile(p); string(b) != want { //nolint:gosec // the test's own temp file
		t.Error("file output differs")
	}
	if err := write(filepath.Join(t.TempDir(), "missing", "x.css"), nil); err == nil {
		t.Error("an unwritable path was accepted")
	}
}

func TestOrdered(t *testing.T) {
	got := ordered([]string{"p-off-8", "p-ok-7", "p-neutral-10", "p-ok-1", "p-neutral-2", "p-accent-0"})
	want := "p-neutral-2 p-neutral-10 p-accent-0 p-ok-1 p-ok-7 p-off-8"
	if strings.Join(got, " ") != want {
		t.Errorf("ordered = %v", got)
	}
}

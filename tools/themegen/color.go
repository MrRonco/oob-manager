package main

import (
	"fmt"
	"math"
	"strconv"
)

// lch is an OKLCH colour: L 0..1, C >= 0, H in degrees.
type lch struct{ L, C, H float64 }

// linear converts to linear-light sRGB (Björn Ottosson's OKLab matrices), unclamped.
// Every product is converted explicitly (float64(x*y)) so the compiler cannot fuse it
// into a multiply-add: arm64 would otherwise round differently from amd64 (CI) and the
// generated file would depend on the machine.
func (c lch) linear() [3]float64 {
	a := float64(c.C * math.Cos(float64(c.H*math.Pi)/180))
	b := float64(c.C * math.Sin(float64(c.H*math.Pi)/180))
	l := cube(c.L + float64(0.3963377774*a) + float64(0.2158037573*b))
	m := cube(c.L - float64(0.1055613458*a) - float64(0.0638541728*b))
	s := cube(c.L - float64(0.0894841775*a) - float64(1.2914855480*b))
	return [3]float64{
		float64(4.0767416621*l) - float64(3.3077115913*m) + float64(0.2309699292*s),
		float64(-1.2684380046*l) + float64(2.6097574011*m) - float64(0.3413193965*s),
		float64(-0.0041960863*l) - float64(0.7034186147*m) + float64(1.7076147010*s),
	}
}

func cube(v float64) float64 { return v * v * v }

const gamutEps = 1e-4

func (c lch) inGamut() bool {
	for _, v := range c.linear() {
		if v < -gamutEps || v > 1+gamutEps {
			return false
		}
	}
	return true
}

// gamutMap lowers chroma (hue and lightness kept) until the colour fits sRGB, so what
// the generator measures is what a browser paints.
func (c lch) gamutMap() lch {
	switch {
	case c.L >= 1:
		return lch{1, 0, c.H}
	case c.L <= 0:
		return lch{0, 0, c.H}
	case c.inGamut():
		return c
	}
	lo, hi := 0.0, c.C
	for range 24 {
		mid := (lo + hi) / 2
		if (lch{c.L, mid, c.H}).inGamut() {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lch{c.L, lo, c.H}
}

func gammaEncode(v float64) float64 {
	v = math.Min(1, math.Max(0, v))
	if v <= 0.0031308 {
		return 12.92 * v
	}
	return float64(1.055*math.Pow(v, 1/2.4)) - 0.055
}

// luminance is the WCAG relative luminance of the 8-bit colour a browser paints.
func (c lch) luminance() float64 {
	var y float64
	for i, v := range c.srgb8() {
		f := float64(v) / 255
		if f <= 0.04045 {
			f /= 12.92
		} else {
			f = math.Pow((f+0.055)/1.055, 2.4)
		}
		y += float64([3]float64{0.2126, 0.7152, 0.0722}[i] * f)
	}
	return y
}

func (c lch) srgb8() [3]int {
	lin := c.gamutMap().linear()
	var out [3]int
	for i, v := range lin {
		out[i] = int(math.Round(gammaEncode(v) * 255))
	}
	return out
}

func (c lch) hex() string {
	v := c.srgb8()
	return fmt.Sprintf("#%02x%02x%02x", v[0], v[1], v[2])
}

func contrast(a, b lch) float64 {
	la, lb := a.luminance(), b.luminance()
	return (math.Max(la, lb) + 0.05) / (math.Min(la, lb) + 0.05)
}

// need is one fitting constraint: at least min:1 against every colour in against.
type need struct {
	against []lch
	min     float64
}

// fit moves L in 0.005 steps (dir +1 lighter, -1 darker) until every constraint holds.
// It measures and returns the colour as written (written()), so a fitted ink cannot
// drop below its ratio when it is rounded into the stylesheet. No convergence within
// 400 steps (L pinned at 0 or 1 without reaching the ratio) is an error.
func fit(c lch, dir float64, needs ...need) (lch, error) {
	for range 400 {
		w, err := c.written()
		if err != nil {
			return lch{}, err
		}
		if satisfied(w, needs) {
			return w, nil
		}
		c.L = math.Min(1, math.Max(0, c.L+float64(dir*0.005)))
	}
	return lch{}, fmt.Errorf("fit %s: no lightness reaches the contrast within 400 steps", c.css())
}

func satisfied(c lch, needs []need) bool {
	for _, n := range needs {
		for _, a := range n.against {
			if contrast(c, a) < n.min {
				return false
			}
		}
	}
	return true
}

// css writes the colour as oklch() with L in percent: the shortest form whose 8-bit
// value equals the gamut-mapped colour's.
func (c lch) css() string {
	g := c.gamutMap()
	l := strconv.FormatFloat(round(g.L*100, 2), 'f', -1, 64) + "%"
	if g.C < 0.0005 {
		return "oklch(" + l + " 0 0)"
	}
	h := math.Mod(math.Mod(g.H, 360)+360, 360)
	return fmt.Sprintf("oklch(%s %s %s)", l, strconv.FormatFloat(floor4(g.C), 'f', -1, 64),
		strconv.FormatFloat(round(h, 1), 'f', -1, 64))
}

// floor4 truncates to 4 decimals; the epsilon keeps a value like 0.12 (0.11999… in
// binary) from losing a whole step.
func floor4(v float64) float64 { return math.Floor(float64(v*1e4)+1e-9) / 1e4 }

func round(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

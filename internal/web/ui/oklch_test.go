package ui

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Test-only colour math for the stylesheet checks: CSS oklch() → OKLab → linear sRGB →
// gamma-encoded sRGB (Björn Ottosson's matrices, the ones CSS Color 4 uses), plus the
// light-dark() split. A colour whose encoded channel needs more than half an 8-bit step
// of clipping is out of the sRGB gamut and is reported, so the tests never pass a value
// the browser would silently clip.

// rgb is a gamma-encoded sRGB colour; channels are NOT clamped (out-of-gamut values
// fall outside 0..1).
type rgb [3]float64

var (
	oklchRE     = regexp.MustCompile(`^oklch\(\s*([0-9.]+)(%?)\s+([0-9.]+)\s+([0-9.]+)\s*\)$`)
	hexColorRE  = regexp.MustCompile(`^#[0-9a-f]{6}$`)
	gamutMargin = 0.5 / 255
)

// oklchToRGB converts OKLCH (L 0..1, C ≥ 0, H in degrees) to encoded sRGB.
func oklchToRGB(l, c, h float64) rgb {
	// Products are converted explicitly (float64(x*y)) so they are never fused into a
	// multiply-add (arm64 rounds those differently from amd64).
	a, b := float64(c*math.Cos(float64(h*math.Pi)/180)), float64(c*math.Sin(float64(h*math.Pi)/180))
	cube := func(v float64) float64 { return v * v * v }
	lc := cube(l + float64(0.3963377774*a) + float64(0.2158037573*b))
	mc := cube(l - float64(0.1055613458*a) - float64(0.0638541728*b))
	sc := cube(l - float64(0.0894841775*a) - float64(1.291485548*b))
	lin := [3]float64{
		float64(4.0767416621*lc) - float64(3.3077115913*mc) + float64(0.2309699292*sc),
		float64(-1.2684380046*lc) + float64(2.6097574011*mc) - float64(0.3413193965*sc),
		float64(-0.0041960863*lc) - float64(0.7034186147*mc) + float64(1.707614701*sc),
	}
	var out rgb
	for i, v := range lin {
		out[i] = encodeSRGB(v)
	}
	return out
}

func encodeSRGB(v float64) float64 {
	if math.Abs(v) <= 0.0031308 {
		return 12.92 * v
	}
	sign := 1.0
	if v < 0 {
		sign = -1
	}
	return sign * (float64(1.055*math.Pow(math.Abs(v), 1/2.4)) - 0.055)
}

// inGamut reports whether every channel rounds into 0..255 without clipping.
func (c rgb) inGamut() bool {
	for _, v := range c {
		if v < -gamutMargin || v > 1+gamutMargin {
			return false
		}
	}
	return true
}

// hex is the 8-bit colour the browser paints (channels clamped, then rounded).
func (c rgb) hex() string {
	var sb strings.Builder
	sb.WriteByte('#')
	for _, v := range c {
		fmt.Fprintf(&sb, "%02x", int(math.Round(math.Min(1, math.Max(0, v))*255)))
	}
	return sb.String()
}

// parseColor reads one CSS colour: oklch(L C H) with L as a percentage or a 0..1
// number, or #rrggbb.
func parseColor(s string) (rgb, error) {
	s = strings.TrimSpace(s)
	if hexColorRE.MatchString(s) {
		var c rgb
		for i := range c {
			v, _ := strconv.ParseUint(s[1+2*i:3+2*i], 16, 8)
			c[i] = float64(v) / 255
		}
		return c, nil
	}
	m := oklchRE.FindStringSubmatch(s)
	if m == nil {
		return rgb{}, fmt.Errorf("unsupported colour %q (want oklch(L C H) or #rrggbb)", s)
	}
	var v [3]float64
	for i, part := range []string{m[1], m[3], m[4]} {
		f, err := strconv.ParseFloat(part, 64)
		if err != nil {
			return rgb{}, fmt.Errorf("colour %q: %w", s, err)
		}
		v[i] = f
	}
	l, c, h := v[0], v[1], v[2]
	if m[2] == "%" {
		l /= 100
	}
	if l > 1 || h > 360 {
		return rgb{}, fmt.Errorf("colour %q out of range", s)
	}
	return oklchToRGB(l, c, h), nil
}

// splitLightDark returns the light and dark arguments of light-dark(a, b), or the
// value twice when it is a plain colour.
func splitLightDark(v string) (light, dark string, err error) {
	v = strings.TrimSpace(v)
	inner, ok := strings.CutPrefix(v, "light-dark(")
	if !ok {
		return v, v, nil
	}
	inner, ok = strings.CutSuffix(inner, ")")
	depth := 0
	for i, r := range inner {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 && ok {
				return strings.TrimSpace(inner[:i]), strings.TrimSpace(inner[i+1:]), nil
			}
		}
	}
	return "", "", fmt.Errorf("malformed light-dark() %q", v)
}

func relLumRGB(c rgb) float64 {
	ch := func(s float64) float64 {
		s = math.Min(1, math.Max(0, s))
		if s <= 0.04045 {
			return s / 12.92
		}
		return math.Pow((s+0.055)/1.055, 2.4)
	}
	return float64(0.2126*ch(c[0])) + float64(0.7152*ch(c[1])) + float64(0.0722*ch(c[2]))
}

// Package firmware is the read-only firmware view's pure logic (docs/tech_doc.md §38):
// version comparison, component kinds, merging the Dell member states into one row per
// component, the "minimum known good" rules, flags, ordering, filters and change
// detection. It reads nothing and writes nothing; firmware updates are out of scope
// (CLAUDE.md rule 11): this package returns versions, never images or update targets.
package firmware

import (
	"strings"
	"unicode"
)

// CompareVersions orders two firmware versions. Both are split on "."; the shorter is
// padded with "0" segments. Numeric segments compare as numbers ("10" > "9", leading
// zeros ignored, no overflow); other segments compare run by run (digits as numbers,
// letters case-insensitively), so "7A" < "10A" and "4239A37" < "4301A73". A number
// against a segment with letters, two segments whose runs do not line up, an empty
// segment or an empty version is incomparable: ok is false and nothing is guessed.
// security.min_firmware uses the same comparison (bmcsec delegates to it).
func CompareVersions(a, b string) (cmp int, ok bool) {
	as, aok := split(a)
	bs, bok := split(b)
	if !aok || !bok {
		return 0, false
	}
	for i := range max(len(as), len(bs)) {
		c, ok := compareSegment(segAt(as, i), segAt(bs, i))
		if !ok {
			return 0, false
		}
		if c != 0 {
			return c, true
		}
	}
	return 0, true
}

func split(v string) ([]string, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, false
	}
	parts := strings.Split(v, ".")
	for _, p := range parts {
		if p == "" || strings.ContainsFunc(p, func(r rune) bool { return !isASCIIAlnum(r) }) {
			return nil, false
		}
	}
	return parts, true
}

func isASCIIAlnum(r rune) bool {
	return r < unicode.MaxASCII && (unicode.IsDigit(r) || unicode.IsLetter(r))
}

func segAt(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return "0"
}

func isDigits(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r < '0' || r > '9' })
}

func compareSegment(x, y string) (int, bool) {
	xd, yd := isDigits(x), isDigits(y)
	switch {
	case xd && yd:
		return compareNumbers(x, y), true
	case xd != yd:
		return 0, false
	}
	xr, yr := runs(x), runs(y)
	if len(xr) != len(yr) {
		return 0, false
	}
	for i := range xr {
		c, ok := compareRun(xr[i], yr[i])
		if !ok {
			return 0, false
		}
		if c != 0 {
			return c, true
		}
	}
	return 0, true
}

func compareRun(x, y string) (int, bool) {
	xd, yd := isDigits(x), isDigits(y)
	switch {
	case xd && yd:
		return compareNumbers(x, y), true
	case xd != yd:
		return 0, false
	default:
		return strings.Compare(strings.ToUpper(x), strings.ToUpper(y)), true
	}
}

// compareNumbers compares two digit strings as unbounded numbers.
func compareNumbers(x, y string) int {
	x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
	if len(x) != len(y) {
		if len(x) < len(y) {
			return -1
		}
		return 1
	}
	return strings.Compare(x, y)
}

// runs splits an alphanumeric segment into alternating digit and letter runs.
func runs(s string) []string {
	var out []string
	start := 0
	for i := 1; i <= len(s); i++ {
		if i == len(s) || isDigits(s[i:i+1]) != isDigits(s[i-1:i]) {
			out = append(out, s[start:i])
			start = i
		}
	}
	return out
}

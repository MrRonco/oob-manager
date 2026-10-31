// Package textclean is the one sanitizer for text a BMC supplied: account names and
// roles, NTP and syslog servers, certificate names, firmware, BIOS and licence text,
// the SSH identification string and algorithm lists. Every reader (Redfish, Dell
// attributes, the network probes) runs BMC strings through Clean before they become a
// fact, so the page, the evidence and every comparison see the same text.
//
// Clean removes what could make text read differently from what it is, or defeat a
// comparison while looking identical: invalid UTF-8; control characters (Cc: escapes,
// bells, tabs, newlines); format characters (Cf: zero-width spaces and joiners, the
// bidirectional embeddings and overrides, the byte order mark, soft hyphens, tag
// characters); and the line and paragraph separators (Zl, Zp). It then trims
// surrounding space and caps the length on a rune boundary. Look-alike letters (a
// Cyrillic о for a Latin o) are graphic characters and stay: the account evidence shows
// any name that is not plain ASCII in Go's quoted form, so they are visible.
package textclean

import (
	"strings"
	"unicode"
)

// Clean returns s without invalid UTF-8 and without Cc, Cf, Zl and Zp runes, trimmed
// and cut to at most n bytes on a rune boundary (n <= 0: no cap).
func Clean(s string, n int) string {
	s = strings.TrimSpace(strings.Map(keep, strings.ToValidUTF8(s, "")))
	if n > 0 && len(s) > n {
		// Cutting may split a rune; drop the invalid tail rather than emit a broken one.
		s = strings.TrimRightFunc(strings.ToValidUTF8(s[:n], ""), unicode.IsSpace)
	}
	return s
}

// keep is the strings.Map rule: -1 drops the rune.
func keep(r rune) rune {
	if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
		return -1
	}
	return r
}

// GraphicASCII reports whether every rune of s is printable ASCII (letters, digits,
// punctuation, space). Text that is not can be shown with strconv.QuoteToASCII so
// look-alike characters are visible.
func GraphicASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsGraphic(r) {
			return false
		}
	}
	return true
}

package metrics

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxLabelValueBytes caps a label value (BMC-supplied names can be arbitrary).
const MaxLabelValueBytes = 64

// SanitizeLabelValue makes a BMC- or admin-supplied string safe and bounded as a label
// value: invalid UTF-8 becomes U+FFFD, control characters are dropped, surrounding
// space is trimmed and the result is cut to MaxLabelValueBytes on a rune boundary.
// Escaping for the wire happens in Write.
func SanitizeLabelValue(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	for len(s) > MaxLabelValueBytes {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

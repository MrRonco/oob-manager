package textclean

import (
	"strings"
	"testing"
)

func TestClean(t *testing.T) {
	cases := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{"plain", "root", 64, "root"},
		{"zero width space", "root\u200b", 64, "root"},
		{"bidi override", "ro\u202eot", 64, "root"},
		{"escape", "root\x1b[31m", 64, "root[31m"},
		{"bell", "root\a", 64, "root"},
		{"byte order mark", "\ufeffroot", 64, "root"},
		{"soft hyphen", "ro\u00adot", 64, "root"},
		{"word joiner", "ro\u2060ot", 64, "root"},
		{"line separator", "a\u2028b", 64, "ab"},
		{"paragraph separator", "a\u2029b", 64, "ab"},
		{"tab and newline", "a\tb\nc", 64, "abc"},
		{"invalid utf-8", "ab\xffc", 64, "abc"},
		{"padding", "  padded \t", 64, "padded"},
		{"only format characters", "\u200b\u202e", 64, ""},
		{"graphic non-ascii kept", "Zoë", 64, "Zoë"},
		{"look-alike kept", "r\u043eot", 64, "r\u043eot"},
		{"cap on a rune boundary", strings.Repeat("é", 10), 5, "éé"},
		{"cap drops trailing space", "ab cd", 3, "ab"},
		{"no cap", strings.Repeat("x", 3000), 0, strings.Repeat("x", 3000)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Clean(c.in, c.n); got != c.want {
				t.Fatalf("Clean(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
			}
		})
	}
}

func TestGraphicASCII(t *testing.T) {
	cases := map[string]bool{"root": true, "oob-ro.1": true, "r\u043eot": false, "Zoë": false, "root\u200b": false,
		"a b": true, "": true}
	for in, want := range cases {
		if got := GraphicASCII(in); got != want {
			t.Errorf("GraphicASCII(%q) = %v, want %v", in, got, want)
		}
	}
}

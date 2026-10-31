package ui

import (
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// motionWords are the CSS that moves something: properties, at-rules and the view
// transition name. Only motion.css may hold them (plan 04 §7).
var motionWords = regexp.MustCompile(`(?i)\b(transition|animation)(-[a-z-]+)?\s*:|@keyframes|@starting-style|@view-transition|view-transition-name`)

const (
	motionAllowed = "@media (prefers-reduced-motion: no-preference)"
	motionReduced = "@media (prefers-reduced-motion: reduce)"
)

// TestMotionOnlyWhenAllowed: every animation, transition and view transition is in
// motion.css, inside prefers-reduced-motion: no-preference (a reduce block may only
// switch a vendored sheet's motion off); durations come from the --dur-* tokens, which
// stay within the 250 ms budget (plan 04 §11 item 5).
func TestMotionOnlyWhenAllowed(t *testing.T) {
	files, err := fs.Glob(staticFS, "static/*.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f == "static/motion.css" {
			continue
		}
		css := cssText(t, f)
		if m := motionWords.FindString(css); m != "" {
			t.Errorf("%s declares motion (%q); motion belongs in motion.css", f, m)
		}
	}

	blocks := topLevelBlocks(t, cssText(t, "static/motion.css"))
	if len(blocks) == 0 {
		t.Fatal("motion.css has no blocks")
	}
	for _, b := range blocks {
		switch b.prelude {
		case motionAllowed:
			if d := regexp.MustCompile(`\d*\.?\d+m?s\b`).FindString(b.body); d != "" {
				t.Errorf("literal duration %q in motion.css; use the --dur-* tokens", d)
			}
		case motionReduced:
			for _, decl := range regexp.MustCompile(`(?i)(transition|animation)[a-z-]*\s*:\s*([^;}]+)`).FindAllStringSubmatch(b.body, -1) {
				if strings.TrimSpace(decl[2]) != "none" {
					t.Errorf("a reduce block may only switch motion off, found %q", decl[0])
				}
			}
		default:
			t.Errorf("motion.css block %q is not inside prefers-reduced-motion", b.prelude)
		}
	}

	tokens := cssText(t, "static/tokens.css")
	durs := regexp.MustCompile(`--dur-\d+:\s*(\d+)ms`).FindAllStringSubmatch(tokens, -1)
	if len(durs) == 0 {
		t.Fatal("no --dur-* tokens in tokens.css")
	}
	for _, d := range durs {
		if ms, _ := strconv.Atoi(d[1]); ms > 250 {
			t.Errorf("duration token %s exceeds the 250 ms budget", d[0])
		}
	}
}

func cssText(t *testing.T, name string) string {
	t.Helper()
	b, err := staticFS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return cssCommentRE.ReplaceAllString(string(b), "")
}

type cssBlock struct{ prelude, body string }

// topLevelBlocks splits a stylesheet into its top-level blocks (prelude and body).
func topLevelBlocks(t *testing.T, css string) []cssBlock {
	t.Helper()
	var out []cssBlock
	depth, start, open := 0, 0, 0
	for i, c := range css {
		switch c {
		case '{':
			if depth == 0 {
				open = i
			}
			depth++
		case '}':
			depth--
			if depth < 0 {
				t.Fatal("unbalanced braces")
			}
			if depth == 0 {
				out = append(out, cssBlock{prelude: strings.Join(strings.Fields(css[start:open]), " "), body: css[open+1 : i]})
				start = i + 1
			}
		}
	}
	if depth != 0 || strings.TrimSpace(css[start:]) != "" {
		t.Fatal("motion.css: unbalanced braces or a declaration outside any block")
	}
	return out
}

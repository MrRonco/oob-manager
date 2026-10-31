package repopolicy

import (
	"maps"
	"regexp"
	"testing"
)

var (
	// GOLANGCI_VERSION    := v2.14.0
	makePin = regexp.MustCompile(`(?m)^([A-Z][A-Z0-9_]*_VERSION)[ \t]*:?=[ \t]*(\S+)[ \t]*$`)
	// "GOLANGCI_VERSION: v2.14.0" in any env block of a workflow (top, job or step level).
	workflowPin = regexp.MustCompile(`(?m)^[ \t]*([A-Z][A-Z0-9_]*_VERSION):[ \t]*(\S+)[ \t]*$`)
)

// pin is one NAME=value occurrence; start and end are the value's byte offsets.
type pin struct {
	name, value string
	start, end  int
}

func findPins(re *regexp.Regexp, text string) []pin {
	var out []pin
	for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
		out = append(out, pin{name: text[m[2]:m[3]], value: text[m[4]:m[5]], start: m[4], end: m[5]})
	}
	return out
}

func pinMap(pins []pin) map[string]string {
	out := map[string]string{}
	for _, p := range pins {
		out[p.name] = p.value
	}
	return out
}

// pinRe returns the pin pattern for a repository file.
func pinRe(path string) *regexp.Regexp {
	if path == "Makefile" {
		return makePin
	}
	return workflowPin
}

// sharedTools are pinned in the Makefile and in ci.yml; CI passes the workflow value to
// make, so a drift would make local runs and CI use different tool versions.
var sharedTools = []string{"GOLANGCI_VERSION", "GOVULNCHECK_VERSION", "ACTIONLINT_VERSION"}

// TestToolPinsAgree: a tool version pinned in the Makefile and in any workflow is the
// same everywhere, and the shared tools are pinned in both the Makefile and ci.yml.
func TestToolPinsAgree(t *testing.T) {
	mk := pinMap(findPins(makePin, readRepoFile(t, "Makefile")))
	ci := pinMap(findPins(workflowPin, readRepoFile(t, ".github/workflows/ci.yml")))
	for _, name := range sharedTools {
		if mk[name] == "" || ci[name] == "" {
			t.Errorf("%s: Makefile %q, ci.yml %q (both must pin it)", name, mk[name], ci[name])
		}
	}
	for _, wf := range workflowPaths(t) {
		for _, p := range findPins(workflowPin, readRepoFile(t, wf)) { // every occurrence, any level
			if v, ok := mk[p.name]; ok && v != p.value {
				t.Errorf("%s drifted: Makefile %s, %s %s", p.name, v, wf, p.value)
			}
		}
	}
}

func TestPinParsers(t *testing.T) {
	mk := pinMap(findPins(makePin, "GOLANGCI_VERSION    := v2.14.0\nCOVER   := 80\n# X_VERSION := no\nBATS_VERSION := 1.13.0\n"))
	if want := map[string]string{"GOLANGCI_VERSION": "v2.14.0", "BATS_VERSION": "1.13.0"}; !maps.Equal(mk, want) {
		t.Errorf("makefile pins %v", mk)
	}
	wf := pinMap(findPins(workflowPin, "env:\n  TRIVY_VERSION: v0.75.0\n  IMAGE: x\njobs:\n  a:\n    env:\n      JOB_VERSION: v9\n    steps:\n      - env:\n\t\t  STEP_VERSION: 1.2\n"))
	if want := map[string]string{"TRIVY_VERSION": "v0.75.0", "JOB_VERSION": "v9", "STEP_VERSION": "1.2"}; !maps.Equal(wf, want) {
		t.Errorf("workflow pins %v", wf)
	}
	p := findPins(workflowPin, "  A_VERSION: v1\n")
	if len(p) != 1 || p[0].start != 13 || p[0].end != 15 {
		t.Errorf("offsets %+v", p)
	}
}

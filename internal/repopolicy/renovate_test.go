package repopolicy

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// packageRule is the part of a Renovate packageRules entry the policy checks.
type packageRule struct {
	MatchManagers               []string `json:"matchManagers"`
	MatchPackageNames           []string `json:"matchPackageNames"`
	MatchUpdateTypes            []string `json:"matchUpdateTypes"`
	DependencyDashboardApproval bool     `json:"dependencyDashboardApproval"`
	GroupName                   string   `json:"groupName"`
}

// renovateConfig is the part of renovate.json the policy depends on.
type renovateConfig struct {
	Extends                    []string `json:"extends"`
	MinimumReleaseAge          string   `json:"minimumReleaseAge"`
	MinimumReleaseAgeBehaviour string   `json:"minimumReleaseAgeBehaviour"`
	InternalChecksFilter       string   `json:"internalChecksFilter"`
	VulnerabilityAlerts        struct {
		MinimumReleaseAge string `json:"minimumReleaseAge"`
	} `json:"vulnerabilityAlerts"`
	PackageRules   []packageRule `json:"packageRules"`
	CustomManagers []struct {
		CustomType          string   `json:"customType"`
		ManagerFilePatterns []string `json:"managerFilePatterns"`
		MatchStrings        []string `json:"matchStrings"`
	} `json:"customManagers"`
}

const releaseAge = "14 days" // CLAUDE.md rule 10

func loadRenovate(t *testing.T) (renovateConfig, map[string]any) {
	t.Helper()
	raw := readRepoFile(t, "renovate.json")
	var cfg renovateConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("renovate.json: %v", err)
	}
	var tree map[string]any
	if err := json.Unmarshal([]byte(raw), &tree); err != nil {
		t.Fatal(err)
	}
	return cfg, tree
}

// TestRenovateKeepsTheFourteenDayRule: no update (security fixes included) is proposed
// before it is 14 days old, a release without a timestamp waits instead of passing,
// actions and Docker bases are pinned by digest, and nothing merges by itself.
func TestRenovateKeepsTheFourteenDayRule(t *testing.T) {
	cfg, tree := loadRenovate(t)
	if cfg.MinimumReleaseAge != releaseAge || cfg.VulnerabilityAlerts.MinimumReleaseAge != releaseAge {
		t.Errorf("minimumReleaseAge %q, vulnerabilityAlerts.minimumReleaseAge %q; both must be %q",
			cfg.MinimumReleaseAge, cfg.VulnerabilityAlerts.MinimumReleaseAge, releaseAge)
	}
	if cfg.MinimumReleaseAgeBehaviour != "timestamp-required" || cfg.InternalChecksFilter != "strict" {
		t.Errorf("minimumReleaseAgeBehaviour %q, internalChecksFilter %q; want timestamp-required, strict",
			cfg.MinimumReleaseAgeBehaviour, cfg.InternalChecksFilter)
	}
	for _, p := range []string{"helpers:pinGitHubActionDigests", "docker:pinDigests"} {
		if !slices.Contains(cfg.Extends, p) {
			t.Errorf("extends lacks %s", p)
		}
	}
	for _, path := range findTrue(tree, "", "automerge", "platformAutomerge") {
		t.Errorf("%s is true: dependency PRs are always reviewed by hand", path)
	}
}

// findTrue returns the JSON paths of every listed key set to true, at any depth.
func findTrue(v any, at string, keys ...string) []string {
	var hits []string
	switch n := v.(type) {
	case map[string]any:
		for k, child := range n {
			if b, ok := child.(bool); ok && b && slices.Contains(keys, k) {
				hits = append(hits, at+"."+k)
			}
			hits = append(hits, findTrue(child, at+"."+k, keys...)...)
		}
	case []any:
		for _, child := range n {
			hits = append(hits, findTrue(child, at+"[]", keys...)...)
		}
	}
	return hits
}

func TestFindTrue(t *testing.T) {
	var tree any
	if err := json.Unmarshal([]byte(`{"automerge":false,"packageRules":[{"automerge":true},{"x":{"platformAutomerge":true}}]}`), &tree); err != nil {
		t.Fatal(err)
	}
	got := findTrue(tree, "", "automerge", "platformAutomerge")
	slices.Sort(got)
	if want := []string{".packageRules[].automerge", ".packageRules[].x.platformAutomerge"}; !slices.Equal(got, want) {
		t.Errorf("got %v", got)
	}
}

// customRegexes compiles the regex custom managers' matchStrings (RE2 accepts this
// JavaScript subset) and their managerFilePatterns ("/…/" regexes; globs are refused so
// the test cannot silently skip a pattern it does not understand).
func customRegexes(t *testing.T, cfg renovateConfig) (matchers, files []*regexp.Regexp) {
	t.Helper()
	for _, m := range cfg.CustomManagers {
		if m.CustomType != "regex" {
			continue
		}
		for _, s := range m.MatchStrings {
			matchers = append(matchers, mustCompile(t, s))
		}
		for _, p := range m.ManagerFilePatterns {
			if len(p) < 2 || p[0] != '/' || p[len(p)-1] != '/' {
				t.Fatalf("managerFilePattern %q: only /regex/ patterns are supported here", p)
			}
			files = append(files, mustCompile(t, p[1:len(p)-1]))
		}
	}
	if len(matchers) == 0 || len(files) == 0 {
		t.Fatal("renovate.json has no regex custom manager with matchStrings and managerFilePatterns")
	}
	return matchers, files
}

func mustCompile(t *testing.T, s string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(s)
	if err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	return re
}

// TestEveryToolPinIsTrackedByRenovate: the Makefile and every workflow file are matched
// by the custom manager's file patterns, and every *_VERSION pin in them is extracted by
// its matchStrings at that exact position (name and value on that line, not an equal
// value elsewhere in the file). A pin without a "# renovate:" line fails here.
func TestEveryToolPinIsTrackedByRenovate(t *testing.T) {
	cfg, _ := loadRenovate(t)
	matchers, files := customRegexes(t, cfg)
	for _, path := range append([]string{"Makefile"}, workflowPaths(t)...) {
		if !slices.ContainsFunc(files, func(re *regexp.Regexp) bool { return re.MatchString(path) }) {
			t.Errorf("%s: no managerFilePatterns entry matches it", path)
			continue
		}
		text := readRepoFile(t, path)
		extracted := extractedSpans(matchers, text)
		for _, p := range findPins(pinRe(path), text) {
			if !extracted[[2]int{p.start, p.end}] {
				t.Errorf("%s: %s=%s is not extracted by the Renovate custom manager (add a \"# renovate:\" line above it)", path, p.name, p.value)
			}
		}
	}
}

// extractedSpans returns the byte spans of every currentValue the matchers capture
// together with a depName.
func extractedSpans(matchers []*regexp.Regexp, text string) map[[2]int]bool {
	out := map[[2]int]bool{}
	for _, re := range matchers {
		dep, val := re.SubexpIndex("depName"), re.SubexpIndex("currentValue")
		if dep < 0 || val < 0 {
			continue
		}
		for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
			if m[2*dep] >= 0 && m[2*val] >= 0 {
				out[[2]int{m[2*val], m[2*val+1]}] = true
			}
		}
	}
	return out
}

func TestExtractedSpansKeysOnPosition(t *testing.T) {
	re := regexp.MustCompile(`# renovate: depName=(?<depName>\S+)\n(?:[A-Z_]+): (?<currentValue>\S+)`)
	text := "A_VERSION: v1\n# renovate: depName=x\nB_VERSION: v1\n"
	spans := extractedSpans([]*regexp.Regexp{re}, text)
	pins := findPins(regexp.MustCompile(`(?m)^([A-Z_]+_VERSION): (\S+)$`), text)
	if len(pins) != 2 || spans[[2]int{pins[0].start, pins[0].end}] || !spans[[2]int{pins[1].start, pins[1].end}] {
		t.Errorf("A (same value, no annotation) must not count as tracked: pins %+v spans %v", pins, spans)
	}
}

// TestActionDigestUpdatesNeedApproval: a moved tag shows up as a digest-only update of
// an action pinned "@<sha> # vX.Y.Z" (same version, new commit), which is exactly what
// a tag rewrite looks like (the March 2026 Trivy compromise). Such PRs are only created
// after someone approves them on the Dependency Dashboard.
func TestActionDigestUpdatesNeedApproval(t *testing.T) {
	cfg, _ := loadRenovate(t)
	held := slices.ContainsFunc(cfg.PackageRules, func(r packageRule) bool {
		return slices.Equal(r.MatchManagers, []string{"github-actions"}) &&
			slices.Equal(r.MatchUpdateTypes, []string{"digest"}) && r.DependencyDashboardApproval
	})
	if !held {
		t.Error("renovate.json: no packageRule {matchManagers: [github-actions], matchUpdateTypes: [digest], dependencyDashboardApproval: true}")
	}
	// A group would carry the digest update into the group's branch next to ordinary
	// bumps; it must get its own branch, held for approval.
	for _, r := range cfg.PackageRules {
		if slices.Contains(r.MatchManagers, "github-actions") && r.GroupName != "" && slices.Contains(r.MatchUpdateTypes, "digest") {
			t.Errorf("renovate.json: group %q includes github-actions digest updates", r.GroupName)
		}
	}
}

// TestCodeownersCoverSupplyChainFiles: changes to workflows, the dependency bot's policy,
// the Makefile gates and the code that enforces them need the maintainer's review (once branch protection requires code-owner review).
func TestCodeownersCoverSupplyChainFiles(t *testing.T) {
	owners := map[string]bool{}
	for _, line := range strings.Split(readRepoFile(t, ".github/CODEOWNERS"), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && !strings.HasPrefix(f[0], "#") && strings.HasPrefix(f[1], "@") {
			owners[f[0]] = true
		}
	}
	for _, p := range []string{"/.github/", "/renovate.json", "/Makefile", "/internal/repopolicy/", "/internal/covergate/"} {
		if !owners[p] {
			t.Errorf(".github/CODEOWNERS has no owner for %s", p)
		}
	}
}

// TestRenovateRegexExtractsIndentedPins: a job- or step-level env pin, however deeply
// indented, is extracted by the real custom manager when annotated (and caught when not).
func TestRenovateRegexExtractsIndentedPins(t *testing.T) {
	cfg, _ := loadRenovate(t)
	matchers, _ := customRegexes(t, cfg)
	text := "jobs:\n  a:\n    env:\n      # renovate: datasource=go depName=example.org/tool\n      TOOL_VERSION: v1.2.3\n" +
		"    steps:\n      - env:\n          OTHER_VERSION: v4\n"
	spans := extractedSpans(matchers, text)
	pins := findPins(workflowPin, text)
	if len(pins) != 2 {
		t.Fatalf("pins %+v", pins)
	}
	if !spans[[2]int{pins[0].start, pins[0].end}] {
		t.Errorf("annotated job-level %s not extracted", pins[0].name)
	}
	if spans[[2]int{pins[1].start, pins[1].end}] {
		t.Errorf("unannotated step-level %s counted as tracked", pins[1].name)
	}
}

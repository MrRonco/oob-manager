package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// profile is a small coverage profile in module example.org/m: package a has 4 of 5
// statements covered (80 %), package b 1 of 4 (25 %); the total is 5 of 9 (55.6 %).
const profile = `mode: atomic
example.org/m/a/x.go:1.1,2.2 2 3
example.org/m/a/x.go:3.1,4.2 2 1
example.org/m/a/y.go:1.1,2.2 1 0
example.org/m/b/z.go:1.1,2.2 1 7
example.org/m/b/z.go:3.1,4.2 3 0
`

func mustParse(t *testing.T, in string) coverage {
	t.Helper()
	cov, err := parseProfile(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	return cov
}

func TestParseProfileCountsStatementsPerPackage(t *testing.T) {
	cov := mustParse(t, profile)
	if got := cov["example.org/m/a"]; got != (counts{Stmts: 5, Covered: 4}) {
		t.Errorf("a = %+v", got)
	}
	if got := cov["example.org/m/b"]; got != (counts{Stmts: 4, Covered: 1}) {
		t.Errorf("b = %+v", got)
	}
	if got := cov.total(); got != (counts{Stmts: 9, Covered: 5}) {
		t.Errorf("total = %+v", got)
	}
}

// A block that appears twice (several test binaries instrumenting the same package)
// counts once, and as covered when any copy ran.
func TestParseProfileMergesDuplicateBlocks(t *testing.T) {
	cov := mustParse(t, "mode: set\nm/p/f.go:1.1,2.2 3 0\nm/p/f.go:1.1,2.2 3 1\nm/p/f.go:5.1,6.2 2 0\n")
	if got := cov["m/p"]; got != (counts{Stmts: 5, Covered: 3}) {
		t.Errorf("p = %+v", got)
	}
}

func TestParseProfileRejectsMalformedInput(t *testing.T) {
	for name, in := range map[string]string{
		"no mode line":  "m/p/f.go:1.1,2.2 1 1\n",
		"empty":         "",
		"short line":    "mode: set\nm/p/f.go:1.1,2.2 1\n",
		"bad stmts":     "mode: set\nm/p/f.go:1.1,2.2 x 1\n",
		"bad count":     "mode: set\nm/p/f.go:1.1,2.2 1 -\n",
		"negative":      "mode: set\nm/p/f.go:1.1,2.2 -1 1\n",
		"no position":   "mode: set\nm/p/f.go 1 1\n",
		"no file in it": "mode: set\n:1.1,2.2 1 1\n",
	} {
		if _, err := parseProfile(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPercentOfEmptyPackageIsZero(t *testing.T) {
	if p := (counts{}).percent(); p != 0 {
		t.Errorf("percent = %v", p)
	}
}

func checkReport(t *testing.T, cov coverage, g gate) (string, bool) {
	t.Helper()
	report, ok := check(cov, g)
	return strings.Join(report, "\n"), ok
}

// Every package in the profile is gated unless excluded, so a new package is gated
// without anyone editing a list.
func TestCheckGatesEveryPackageByDefault(t *testing.T) {
	cov := mustParse(t, profile)
	report, ok := checkReport(t, cov, gate{minPct: 50, module: "example.org/m"})
	if ok {
		t.Fatalf("b at 25 %% passed a 50 %% gate:\n%s", report)
	}
	for _, want := range []string{"ok   total 55.6%", "ok   example.org/m/a 80.0%", "FAIL example.org/m/b 25.0% < 50%"} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %q:\n%s", want, report)
		}
	}
}

func TestCheckSkipsExcludedPackages(t *testing.T) {
	cov := mustParse(t, profile)
	report, ok := checkReport(t, cov, gate{minPct: 50, module: "example.org/m", exclude: []string{"b"}})
	if !ok {
		t.Fatalf("excluded b still failed:\n%s", report)
	}
	if !strings.Contains(report, "skip example.org/m/b 25.0% (excluded)") {
		t.Errorf("report does not show the exclusion:\n%s", report)
	}
}

// An exclusion that no longer matches a package fails, so the list cannot rot.
func TestCheckFailsAStaleExclusion(t *testing.T) {
	cov := mustParse(t, profile)
	report, ok := checkReport(t, cov, gate{minPct: 10, module: "example.org/m", exclude: []string{"gone"}})
	if ok || !strings.Contains(report, "FAIL example.org/m/gone: excluded but not in the profile") {
		t.Fatalf("stale exclusion passed:\n%s", report)
	}
}

// A required package missing from the profile (renamed, moved, or no statements) fails.
func TestCheckFailsAMissingRequiredPackage(t *testing.T) {
	cov := mustParse(t, profile)
	report, ok := checkReport(t, cov, gate{minPct: 10, module: "example.org/m", required: []string{"a", "gone"}})
	if ok || !strings.Contains(report, "FAIL example.org/m/gone: required but not in the profile") {
		t.Fatalf("missing required package passed:\n%s", report)
	}
}

func TestCheckRejectsARequiredPackageThatIsExcluded(t *testing.T) {
	cov := mustParse(t, profile)
	report, ok := checkReport(t, cov, gate{minPct: 10, module: "example.org/m", required: []string{"b"}, exclude: []string{"b"}})
	if ok || !strings.Contains(report, "FAIL example.org/m/b: required and excluded") {
		t.Fatalf("required+excluded passed:\n%s", report)
	}
}

func TestCheckWithoutModuleTakesFullImportPaths(t *testing.T) {
	cov := mustParse(t, profile)
	if report, ok := checkReport(t, cov, gate{minPct: 20, required: []string{"example.org/m/a"}}); !ok {
		t.Fatalf("full paths failed:\n%s", report)
	}
}

// The comparison is exact, not on the rounded figure.
func TestCheckBoundaries(t *testing.T) {
	exact := coverage{"m/p": {Stmts: 5, Covered: 4}} // exactly 80 %
	if report, ok := checkReport(t, exact, gate{minPct: 80}); !ok {
		t.Errorf("exactly 80 %% failed an 80 %% gate:\n%s", report)
	}
	below := coverage{"m/p": {Stmts: 3125, Covered: 2499}} // 79.968 %, prints as 80.0 %
	report, ok := checkReport(t, below, gate{minPct: 80})
	if ok {
		t.Errorf("79.968 %% passed an 80 %% gate:\n%s", report)
	}
	if !strings.Contains(report, "FAIL m/p 80.0% < 80%") {
		t.Errorf("report:\n%s", report)
	}
}

// A profile with no statements at all is a broken run, not 100 % coverage.
func TestCheckFailsAnEmptyTotal(t *testing.T) {
	if report, ok := checkReport(t, coverage{}, gate{minPct: 80}); ok {
		t.Fatalf("empty profile passed:\n%s", report)
	}
	if report, ok := checkReport(t, coverage{"m/p": {}}, gate{minPct: 0}); ok {
		t.Fatalf("zero statements passed a 0 %% gate:\n%s", report)
	}
}

// Packages with no statements (test-only packages such as repopolicy) are not gated.
func TestCheckIgnoresPackagesWithoutStatements(t *testing.T) {
	cov := mustParse(t, profile)
	cov["example.org/m/testonly"] = counts{}
	if report, ok := checkReport(t, cov, gate{minPct: 20, module: "example.org/m"}); !ok || strings.Contains(report, "testonly") {
		t.Fatalf("a package without statements was gated:\n%s", report)
	}
}

func writeProfile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cover.out")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunExitCodes(t *testing.T) {
	p := writeProfile(t, profile)
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"pass", []string{"-profile", p, "-min", "25", "-module", "example.org/m", "a", "b"}, 0},
		{"package below", []string{"-profile", p, "-min", "50", "-module", "example.org/m"}, 1},
		{"excluded", []string{"-profile", p, "-min", "50", "-module", "example.org/m", "-exclude", "b"}, 0},
		{"exclude list", []string{"-profile", p, "-min", "50", "-module", "example.org/m", "-exclude", " a  b "}, 0},
		{"total below", []string{"-profile", p, "-min", "60", "-exclude", "example.org/m/b"}, 1},
		{"missing profile", []string{"-profile", filepath.Join(t.TempDir(), "none"), "-min", "1"}, 2},
		{"bad flag", []string{"-nope"}, 2},
		{"min out of range", []string{"-profile", p, "-min", "101"}, 2},
		{"no profile flag", []string{"-min", "80"}, 2},
	}
	for _, c := range cases {
		var out, errOut bytes.Buffer
		if got := run(c.args, &out, &errOut); got != c.want {
			t.Errorf("%s: exit %d, want %d\nstdout:\n%s\nstderr:\n%s", c.name, got, c.want, out.String(), errOut.String())
		}
	}
}

func TestRunPrintsTotalAndPackages(t *testing.T) {
	p := writeProfile(t, profile)
	var out, errOut bytes.Buffer
	if code := run([]string{"-profile", p, "-min", "25", "-module", "example.org/m", "b"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, want := range []string{"ok   total 55.6%", "ok   example.org/m/a 80.0%", "ok   example.org/m/b 25.0%"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
}

func TestRunRejectsAMalformedProfile(t *testing.T) {
	p := writeProfile(t, "garbage\n")
	var out, errOut bytes.Buffer
	if code := run([]string{"-profile", p, "-min", "80"}, &out, &errOut); code != 2 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errOut.String(), "covergate:") {
		t.Errorf("stderr: %q", errOut.String())
	}
}

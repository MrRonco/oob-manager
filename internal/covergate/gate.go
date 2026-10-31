package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"
)

// counts is the statement tally of one package (or of the whole profile).
type counts struct {
	Stmts   int
	Covered int
}

// percent is the statement coverage in percent; a package with no statements is 0 %.
func (c counts) percent() float64 {
	if c.Stmts == 0 {
		return 0
	}
	return float64(c.Covered) * 100 / float64(c.Stmts)
}

// meets reports whether the coverage is at least minPct percent (no rounding: 79.968 %
// fails an 80 % gate even though it prints as 80.0 %). No statements never meets a gate:
// an empty profile is a broken run, not full coverage.
func (c counts) meets(minPct float64) bool {
	return c.Stmts > 0 && float64(c.Covered)*100 >= minPct*float64(c.Stmts)
}

// coverage maps a package import path to its tally.
type coverage map[string]counts

func (cov coverage) total() counts {
	var t counts
	for _, c := range cov {
		t.Stmts += c.Stmts
		t.Covered += c.Covered
	}
	return t
}

// block is one profile line: a source range, its statement count and whether it ran.
type block struct {
	pos     string // "import/path/file.go:1.1,2.2"
	stmts   int
	covered bool
}

// parseProfile reads a `go test -coverprofile` file (any mode) and tallies statements
// per package. A block listed more than once counts once, as covered if any copy ran.
func parseProfile(r io.Reader) (coverage, error) {
	sc := bufio.NewScanner(r)
	if !sc.Scan() || !strings.HasPrefix(sc.Text(), "mode: ") {
		return nil, errors.New("not a coverage profile: first line must be \"mode: …\"")
	}
	blocks := map[string]block{}
	for n := 2; sc.Scan(); n++ {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		b, err := parseBlock(sc.Text())
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		if prev, seen := blocks[b.pos]; seen {
			b.covered = b.covered || prev.covered
		}
		blocks[b.pos] = b
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	cov := coverage{}
	for _, b := range blocks {
		file, _, _ := strings.Cut(b.pos, ":")
		pkg := path.Dir(file)
		c := cov[pkg]
		c.Stmts += b.stmts
		if b.covered {
			c.Covered += b.stmts
		}
		cov[pkg] = c
	}
	return cov, nil
}

func parseBlock(line string) (block, error) {
	f := strings.Fields(line)
	if len(f) != 3 {
		return block{}, fmt.Errorf("want \"file:range stmts count\", got %q", line)
	}
	file, rng, ok := strings.Cut(f[0], ":")
	if !ok || file == "" || rng == "" {
		return block{}, fmt.Errorf("bad position %q", f[0])
	}
	stmts, err := strconv.Atoi(f[1])
	if err != nil || stmts < 0 {
		return block{}, fmt.Errorf("bad statement count %q", f[1])
	}
	count, err := strconv.Atoi(f[2])
	if err != nil || count < 0 {
		return block{}, fmt.Errorf("bad hit count %q", f[2])
	}
	return block{pos: f[0], stmts: stmts, covered: count > 0}, nil
}

// gate says what check enforces. required and exclude are package paths relative to
// module (full import paths when module is empty).
type gate struct {
	minPct   float64
	module   string
	required []string // must be in the profile (a rename cannot drop a key package)
	exclude  []string // not gated; each must still be in the profile (no stale entries)
}

func (g gate) path(p string) string {
	if g.module == "" {
		return p
	}
	return g.module + "/" + p
}

// check gates the module total and every package in the profile that has statements,
// except the excluded ones. It returns one report line per package and whether every
// gate passed. A required or excluded package missing from the profile fails.
func check(cov coverage, g gate) ([]string, bool) {
	ok := true
	fail := func(line string) string { ok = false; return line }
	line := func(name string, c counts) string {
		if c.meets(g.minPct) {
			return fmt.Sprintf("ok   %s %.1f%%", name, c.percent())
		}
		return fail(fmt.Sprintf("FAIL %s %.1f%% < %g%%", name, c.percent(), g.minPct))
	}
	excluded := map[string]bool{}
	for _, p := range g.exclude {
		excluded[g.path(p)] = true
	}
	report := []string{line("total", cov.total())}
	for _, pkg := range slices.Sorted(maps.Keys(cov)) {
		switch c := cov[pkg]; {
		case c.Stmts == 0:
		case excluded[pkg]:
			report = append(report, fmt.Sprintf("skip %s %.1f%% (excluded)", pkg, c.percent()))
		default:
			report = append(report, line(pkg, c))
		}
	}
	for _, p := range g.required {
		switch pkg := g.path(p); {
		case excluded[pkg]:
			report = append(report, fail("FAIL "+pkg+": required and excluded"))
		case cov[pkg].Stmts == 0:
			report = append(report, fail("FAIL "+pkg+": required but not in the profile (renamed, moved or no statements?)"))
		}
	}
	for _, p := range g.exclude {
		if cov[g.path(p)].Stmts == 0 {
			report = append(report, fail("FAIL "+g.path(p)+": excluded but not in the profile (drop it from the list)"))
		}
	}
	return report, ok
}

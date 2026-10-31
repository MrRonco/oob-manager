package repopolicy

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var fuzzFunc = regexp.MustCompile(`(?m)^func (Fuzz\w+)\(f \*testing\.F\)`)

// TestFuzzTargetsListed: every fuzz function in the tree is in exactly one of the
// Makefile's nightly sets (FUZZ_A, FUZZ_B), and every listed target exists, so a new
// target cannot be skipped by the nightly job and a rename cannot leave a dead entry.
func TestFuzzTargetsListed(t *testing.T) {
	mk := readRepoFile(t, "Makefile")
	listed := append(makeVar(mk, "FUZZ_A"), makeVar(mk, "FUZZ_B")...)
	var found []string
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, err := os.ReadFile(p) //nolint:gosec // G304: the repository's own test files
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, filepath.Dir(p))
		for _, m := range fuzzFunc.FindAllStringSubmatch(string(b), -1) {
			found = append(found, "./"+filepath.ToSlash(rel)+":"+m[1])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) == 0 {
		t.Fatal("no fuzz targets found: the scan is broken")
	}
	for _, f := range found {
		if n := countOf(listed, f); n != 1 {
			t.Errorf("%s is listed %d times in FUZZ_A/FUZZ_B (want 1)", f, n)
		}
	}
	for _, l := range listed {
		if !slices.Contains(found, l) {
			t.Errorf("%s is listed in the Makefile but does not exist", l)
		}
	}
	if wf := readRepoFile(t, ".github/workflows/nightly.yml"); !strings.Contains(wf, "make fuzz") {
		t.Error("nightly.yml does not run make fuzz")
	}
}

func countOf(list []string, s string) int {
	n := 0
	for _, x := range list {
		if x == s {
			n++
		}
	}
	return n
}

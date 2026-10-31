package repopolicy

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// makeVar returns the words of a Makefile ":=" variable, following "\" continuations.
func makeVar(makefile, name string) []string {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `[ \t]*:=((?:[^\n]*\\\n)*[^\n]*)`)
	m := re.FindStringSubmatch(makefile)
	if m == nil {
		return nil
	}
	return strings.Fields(strings.ReplaceAll(m[1], "\\\n", " "))
}

func TestMakeVarFollowsContinuations(t *testing.T) {
	mk := "A := x y \\\n     z\nB := q\n"
	if got := makeVar(mk, "A"); !slices.Equal(got, []string{"x", "y", "z"}) {
		t.Errorf("A = %v", got)
	}
	if got := makeVar(mk, "C"); got != nil {
		t.Errorf("C = %v", got)
	}
}

func modulePath(t *testing.T) string {
	t.Helper()
	for _, line := range strings.Split(readRepoFile(t, "go.mod"), "\n") {
		if mod, ok := strings.CutPrefix(line, "module "); ok {
			return strings.TrimSpace(mod)
		}
	}
	t.Fatal("go.mod has no module line")
	return ""
}

// TestCoverExcludedPackagesAreNotShipped: the coverage gate skips COVER_EXCLUDE on the
// grounds that those test doubles are never part of the binary. No non-test Go file
// outside them may import one, so the exclusion cannot hide shipped code.
func TestCoverExcludedPackagesAreNotShipped(t *testing.T) {
	excluded := makeVar(readRepoFile(t, "Makefile"), "COVER_EXCLUDE")
	if len(excluded) == 0 {
		t.Fatal("Makefile has no COVER_EXCLUDE; the parser is broken")
	}
	mod := modulePath(t)
	banned := map[string]bool{}
	for _, p := range excluded {
		banned[mod+"/"+p] = true
	}
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			rel, err := filepath.Rel(root, filepath.Dir(p))
			if err != nil || banned[mod+"/"+filepath.ToSlash(rel)] {
				return err // the doubles may use each other
			}
			f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imp := range f.Imports {
				if path, _ := strconv.Unquote(imp.Path.Value); banned[path] {
					t.Errorf("%s imports %s, which make cover excludes (COVER_EXCLUDE)", filepath.ToSlash(rel), path)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

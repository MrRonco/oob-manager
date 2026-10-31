package repopolicy

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// root is the repository root, relative to this package's directory.
const root = "../.."

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// directRequires returns the module paths go.mod requires directly (no "// indirect"),
// from both the block and the single-line form.
func directRequires(gomod string) []string {
	var mods []string
	inBlock := false
	sc := bufio.NewScanner(strings.NewReader(gomod))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "require (":
			inBlock = true
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		case strings.HasPrefix(line, "require "):
			line = strings.TrimPrefix(line, "require ")
		case !inBlock:
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 && !strings.Contains(line, "// indirect") {
			mods = append(mods, f[0])
		}
	}
	return mods
}

// section returns the lines of the markdown section that starts with heading, up to the
// next heading of the same level.
func section(md, heading string) string {
	start := strings.Index("\n"+md, "\n"+heading)
	if start < 0 {
		return ""
	}
	rest := md[start:]
	if end := strings.Index(rest[len(heading):], "\n## "); end >= 0 {
		return rest[:len(heading)+end]
	}
	return rest
}

var backticked = regexp.MustCompile("`([^`]+)`")

// libraryModules returns every backticked token in the Module column (the second cell)
// of the table in tech_doc §2.
func libraryModules(sec string) []string {
	var mods []string
	for _, line := range strings.Split(sec, "\n") {
		cells := strings.Split(line, "|")
		if len(cells) < 4 || !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}
		for _, m := range backticked.FindAllStringSubmatch(cells[2], -1) {
			mods = append(mods, m[1])
		}
	}
	return mods
}

// undocumented returns the modules with no documented path equal to them or below
// them (a row for golang.org/x/crypto/argon2 documents golang.org/x/crypto).
func undocumented(required, documented []string) []string {
	var missing []string
	for _, mod := range required {
		ok := slices.ContainsFunc(documented, func(d string) bool {
			return d == mod || strings.HasPrefix(d, mod+"/")
		})
		if !ok {
			missing = append(missing, mod)
		}
	}
	return missing
}

// vendorDirs returns the top-level directories named in vendor.sha256 (one per
// vendored package, e.g. "novnc-1.7.0").
func vendorDirs(manifest string) []string {
	var dirs []string
	for _, line := range strings.Split(strings.TrimSpace(manifest), "\n") {
		_, name, ok := strings.Cut(line, "  ")
		dir, _, nested := strings.Cut(name, "/")
		if ok && nested && !slices.Contains(dirs, dir) {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

const libraries = "## 2. Libraries"

// TestDependenciesDocumented is CLAUDE.md rule 10 as a test: every direct go.mod
// requirement has a row in tech_doc §2 (purpose, licence, why not stdlib).
func TestDependenciesDocumented(t *testing.T) {
	sec := section(readRepoFile(t, "docs/tech_doc.md"), libraries)
	if sec == "" {
		t.Fatalf("tech_doc.md has no %q section", libraries)
	}
	required := directRequires(readRepoFile(t, "go.mod"))
	if len(required) == 0 {
		t.Fatal("found no direct requirements in go.mod; the parser is broken")
	}
	for _, mod := range undocumented(required, libraryModules(sec)) {
		t.Errorf("go.mod requires %s but docs/tech_doc.md §2 has no row for it", mod)
	}
}

// TestVendoredAssetsDocumented: every vendored front-end package (a top-level
// directory in vendor.sha256) is named in tech_doc §2 and has a NOTICE entry.
func TestVendoredAssetsDocumented(t *testing.T) {
	dirs := vendorDirs(readRepoFile(t, "internal/web/ui/vendor.sha256"))
	if len(dirs) == 0 {
		t.Fatal("found no vendored directories in vendor.sha256; the parser is broken")
	}
	sec := section(readRepoFile(t, "docs/tech_doc.md"), libraries)
	notice := readRepoFile(t, "NOTICE")
	for _, d := range dirs {
		if !strings.Contains(sec, d+"/") {
			t.Errorf("vendored %s/ is not named in docs/tech_doc.md §2", d)
		}
		if !strings.Contains(notice, "internal/web/ui/static/vendor/"+d+"/") {
			t.Errorf("vendored %s/ has no NOTICE entry", d)
		}
	}
}

func TestDirectRequiresParser(t *testing.T) {
	gomod := "module m\n\nrequire single.example/a v1.0.0\nrequire (\n\tx.example/b v1.2.3 // indirect\n" +
		"\tx.example/c v0.1.0\n)\nrequire (\n\tx.example/d v2.0.0\n)\nreplace x.example/c => ../c\n"
	if got, want := directRequires(gomod), []string{"single.example/a", "x.example/c", "x.example/d"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestUndocumentedMatchesModuleOrSubpackage(t *testing.T) {
	sec := "## 2. Libraries\n\n| Purpose | Module | License |\n|---|---|---|\n" +
		"| Hashing | `golang.org/x/crypto/argon2` | BSD-3 |\n| Config | `gopkg.in/yaml.v3` + validation | MIT |\n" +
		"| Mentioned elsewhere | none | `example.com/not-a-module-cell` |\n\n## 3. Next\n| x | `late.example/m` | y |\n"
	doc := libraryModules(section(sec, libraries))
	got := undocumented([]string{"golang.org/x/crypto", "gopkg.in/yaml.v3", "golang.org/x/cryptography",
		"example.com/not-a-module-cell", "late.example/m"}, doc)
	want := []string{"golang.org/x/cryptography", "example.com/not-a-module-cell", "late.example/m"}
	if !slices.Equal(got, want) {
		t.Errorf("undocumented = %v, want %v (documented %v)", got, want, doc)
	}
}

func TestVendorDirsParser(t *testing.T) {
	manifest := "aa  lib-1.0/a.js\nbb  lib-1.0/sub/b.js\ncc  other-2.0/LICENSE\ndd  stray.js\n"
	if got, want := vendorDirs(manifest), []string{"lib-1.0", "other-2.0"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

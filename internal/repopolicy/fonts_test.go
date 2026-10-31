package repopolicy

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// fontBuilds is the APPEND-ONLY ledger of every font file ever shipped, keyed by its
// path under static/vendor/fonts/. The fonts are served with a one-year immutable
// cache and no ?v= query, so a URL must never change content: new bytes (a new upstream
// release, or a new subset of the same one) go into a new directory,
// <family>-<upstream version>[-r<N>], with a new entry here. Never edit an entry.
var fontBuilds = map[string]string{
	"inter-4.1/inter-var-latin.woff2":                     "d9eab0e0b0eb9d3a39b1cc3e7db9482d008d8da0cfae413333ad708400cde60b",
	"jetbrains-mono-2.304/jetbrains-mono-var-latin.woff2": "d28e451b398ad90050633ecdf8b96d4bb9d85c7f2e558fe70b7ecfb8b0565651",
}

var fontDirName = regexp.MustCompile(`^([a-z]+(?:-[a-z]+)*)-([0-9]+(?:\.[0-9]+)*)(?:-r[0-9]+)?$`)

// vendoredFontHashes returns path-under-fonts/ → SHA-256 for every woff2 in the
// manifest (the ui package's vendor test proves the bytes match the manifest).
func vendoredFontHashes(manifest string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(manifest, "\n") {
		sum, name, ok := strings.Cut(line, "  ")
		if rest, isFont := strings.CutPrefix(name, "fonts/"); ok && isFont && strings.HasSuffix(rest, ".woff2") {
			out[rest] = sum
		}
	}
	return out
}

// fontVersionProblems checks the rule above for one manifest against the ledger.
func fontVersionProblems(hashes, ledger map[string]string) []string {
	var bad []string
	for path, sum := range hashes {
		dir, _, _ := strings.Cut(path, "/")
		if !fontDirName.MatchString(dir) {
			bad = append(bad, dir+": font directories are named <family>-<version>[-rN]")
		}
		want, known := ledger[path]
		switch {
		case !known:
			bad = append(bad, path+": not in the fontBuilds ledger (add an entry for a NEW directory)")
		case want != sum:
			bad = append(bad, path+": its bytes changed in place; new font bytes need a new versioned directory")
		}
	}
	slices.Sort(bad)
	return bad
}

// TestFontBuildsAreAppendOnly: every vendored woff2 is in the ledger with the same
// hash, in a <family>-<version> directory.
func TestFontBuildsAreAppendOnly(t *testing.T) {
	hashes := vendoredFontHashes(readRepoFile(t, "internal/web/ui/vendor.sha256"))
	if len(hashes) == 0 {
		t.Fatal("no fonts/*.woff2 in vendor.sha256; the parser is broken")
	}
	for _, p := range fontVersionProblems(hashes, fontBuilds) {
		t.Error(p)
	}
}

// TestFontBuildScriptMatchesVendoredVersions: tools/fonts/build-fonts.sh rebuilds
// exactly the vendored versions (its version variables name the vendored directories).
func TestFontBuildScriptMatchesVendoredVersions(t *testing.T) {
	script := readRepoFile(t, "tools/fonts/build-fonts.sh")
	hashes := vendoredFontHashes(readRepoFile(t, "internal/web/ui/vendor.sha256"))
	for variable, family := range map[string]string{"INTER_VERSION": "inter", "JBMONO_VERSION": "jetbrains-mono"} {
		m := regexp.MustCompile(`(?m)^` + variable + `=(\S+)$`).FindStringSubmatch(script)
		if m == nil {
			t.Errorf("build-fonts.sh has no %s=", variable)
			continue
		}
		dir := family + "-" + m[1] + "/"
		found := false
		for p := range hashes {
			found = found || strings.HasPrefix(p, dir)
		}
		if !found {
			t.Errorf("build-fonts.sh builds %s, but vendor.sha256 has no fonts/%s", dir, dir)
		}
	}
}

func TestFontVersionProblems(t *testing.T) {
	ledger := map[string]string{"inter-4.1/a.woff2": "aa"}
	if bad := fontVersionProblems(map[string]string{"inter-4.1/a.woff2": "aa"}, ledger); len(bad) != 0 {
		t.Errorf("clean manifest reported %v", bad)
	}
	bad := fontVersionProblems(map[string]string{"inter-4.1/a.woff2": "bb", "inter/b.woff2": "cc", "inter-4.1-r2/a.woff2": "dd"}, ledger)
	want := []string{
		"inter-4.1-r2/a.woff2: not in the fontBuilds ledger (add an entry for a NEW directory)",
		"inter-4.1/a.woff2: its bytes changed in place; new font bytes need a new versioned directory",
		"inter/b.woff2: not in the fontBuilds ledger (add an entry for a NEW directory)",
		"inter: font directories are named <family>-<version>[-rN]",
	}
	if !slices.Equal(bad, want) {
		t.Errorf("got %q\nwant %q", bad, want)
	}
	if got := vendoredFontHashes("aa  fonts/x-1/a.woff2\nbb  fonts/x-1/OFL.txt\ncc  novnc-1/a.js\n"); len(got) != 1 || got["x-1/a.woff2"] != "aa" {
		t.Errorf("vendoredFontHashes = %v", got)
	}
}

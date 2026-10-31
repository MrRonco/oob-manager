package repopolicy

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// relPaths returns the repository-relative (forward-slash) paths under dir whose base
// name matches one of the patterns, recursively when deep is set.
func relPaths(t *testing.T, dir string, deep bool, patterns ...string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(dir)), func(p string, d fs.DirEntry, err error) error {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil
		case err != nil:
			return err
		case d.IsDir() && !deep && filepath.Base(p) != filepath.Base(dir):
			return fs.SkipDir
		case d.IsDir():
			return nil
		}
		if slices.ContainsFunc(patterns, func(pat string) bool { ok, _ := path.Match(pat, d.Name()); return ok }) {
			rel, err := filepath.Rel(root, p)
			out = append(out, filepath.ToSlash(rel))
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

// workflowPaths returns every workflow file.
func workflowPaths(t *testing.T) []string {
	t.Helper()
	paths := relPaths(t, ".github/workflows", false, "*.yml", "*.yaml")
	if len(paths) == 0 {
		t.Fatal("no workflow files found")
	}
	return paths
}

// actionPaths returns every local (composite) action definition.
func actionPaths(t *testing.T) []string {
	t.Helper()
	return relPaths(t, ".github/actions", true, "action.yml", "action.yaml")
}

var (
	// Block-style "uses:" lines, the only style allowed (the tag comment lives on them).
	usesLine = regexp.MustCompile(`(?m)^[ \t]*(?:-[ \t]+)?["']?uses["']?[ \t]*:[ \t]*["']?([^\s"'#]+)["']?(.*)$`)
	// owner/repo[/path]@<40 hex>, then "# v<tag>" (the tag Renovate and humans read).
	pinnedRef  = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$`)
	tagComment = regexp.MustCompile(`^\s+#\s+v\d\S*`)
)

// yamlDocs decodes every document in the file (a second "---" document is checked too).
func yamlDocs(text string) ([]any, error) {
	dec := yaml.NewDecoder(strings.NewReader(text))
	var docs []any
	for {
		var doc any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return nil, err
		}
		docs = append(docs, doc)
	}
}

// usesMaps calls visit for every mapping, at any depth, that has a "uses" key: steps
// (jobs.*.steps[], runs.steps[]) and reusable-workflow jobs (jobs.*.uses) alike, in any
// YAML style.
func usesMaps(node any, visit func(map[string]any)) {
	switch n := node.(type) {
	case map[string]any:
		if _, ok := n["uses"]; ok {
			visit(n)
		}
		for _, k := range slices.Sorted(maps.Keys(n)) {
			usesMaps(n[k], visit)
		}
	case []any:
		for _, c := range n {
			usesMaps(c, visit)
		}
	}
}

// refProblem checks one "uses" value. A local "./" reference is allowed only when it
// points at a file this test also checks.
func refProblem(ref string, checked func(string) bool) string {
	if local, ok := strings.CutPrefix(ref, "./"); ok {
		local = strings.TrimSuffix(local, "/")
		if checked(local) || checked(local+"/action.yml") || checked(local+"/action.yaml") {
			return ""
		}
		return fmt.Sprintf("uses %s: local reference to a file that is not checked", ref)
	}
	if !pinnedRef.MatchString(ref) {
		return fmt.Sprintf("uses %s: not pinned to a full commit SHA", ref)
	}
	return ""
}

// usesProblems checks every "uses" in the parsed documents, and cross-checks them with
// the block-style lines: a count mismatch means a flow-style "uses" (no tag comment
// possible, invisible to line tools), which is refused.
func usesProblems(text string, docs []any, checked func(string) bool) []string {
	var problems []string
	parsed := 0
	for _, d := range docs {
		usesMaps(d, func(m map[string]any) {
			parsed++
			ref, ok := m["uses"].(string)
			if !ok {
				problems = append(problems, fmt.Sprintf("uses %v: not a string", m["uses"]))
			} else if p := refProblem(ref, checked); p != "" {
				problems = append(problems, p)
			}
		})
	}
	lines := usesLine.FindAllStringSubmatch(text, -1)
	if len(lines) != parsed {
		problems = append(problems, fmt.Sprintf("%d uses in the YAML but %d block-style \"uses:\" lines (write every step in block style)", parsed, len(lines)))
	}
	for _, m := range lines {
		if !strings.HasPrefix(m[1], "./") && pinnedRef.MatchString(m[1]) && !tagComment.MatchString(m[2]) {
			problems = append(problems, fmt.Sprintf("uses %s: no \"# v…\" tag comment", m[1]))
		}
	}
	return problems
}

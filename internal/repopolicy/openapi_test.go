package repopolicy

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var (
	// mux.Handle("/api/v1/servers", …) or mux.Handle(PathHealth, …)
	muxRoute = regexp.MustCompile(`mux\.Handle\((?:"([^"]+)"|([A-Z][A-Za-z]*)),`)
	// const PathHealth = "/healthz" or a PathX = "…" line inside a const block
	pathConst = regexp.MustCompile(`(?m)\b(Path[A-Za-z]*)\s*=\s*"([^"]+)"`)
)

// apiRoutes returns the paths internal/api registers, without the "/api/" catch-all.
func apiRoutes(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(root, "internal", "api", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	consts := map[string]string{}
	var src strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f) //nolint:gosec // G304: the repository's own sources
		if err != nil {
			t.Fatal(err)
		}
		src.Write(b)
		for _, m := range pathConst.FindAllStringSubmatch(string(b), -1) {
			consts[m[1]] = m[2]
		}
	}
	var routes []string
	for _, m := range muxRoute.FindAllStringSubmatch(src.String(), -1) {
		p := m[1]
		if p == "" {
			if p = consts[m[2]]; p == "" {
				t.Fatalf("route constant %s not found", m[2])
			}
		}
		if p != "/api/" {
			routes = append(routes, p)
		}
	}
	sort.Strings(routes)
	return routes
}

// TestOpenAPICoversEveryRoute keeps docs/api/openapi.yaml honest: every route registered
// in internal/api is documented as a GET, and nothing is documented that is not served.
func TestOpenAPICoversEveryRoute(t *testing.T) {
	routes := apiRoutes(t)
	if len(routes) < 10 {
		t.Fatalf("found only %d routes: the scan is broken", len(routes))
	}
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "docs/api/openapi.yaml")), &doc); err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		ops, ok := doc.Paths[r]
		if !ok {
			t.Errorf("%s is served but missing from docs/api/openapi.yaml", r)
			continue
		}
		for method := range ops {
			if method != "get" {
				t.Errorf("%s documents %s; the API is read-only", r, method)
			}
		}
	}
	for p := range doc.Paths {
		if !slices.Contains(routes, p) {
			t.Errorf("%s is documented but not served by internal/api", p)
		}
	}
}

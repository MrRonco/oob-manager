package ui

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestVendoredFilesMatchManifest re-verifies every vendored file against vendor.sha256
// (security.md §6): the unmodified noVNC 1.7.0 release (MPL-2.0, file-level copyleft) and
// xterm.js 6.0.0 + addon-fit 0.11.0 (MIT, npm tarballs checked against the registry
// shasum), the Inter 4.1 and JetBrains Mono 2.304 woff2 subsets (SIL OFL 1.1, with
// their licence texts), the Lucide 1.53.0 icon sources (ISC, unserved, in iconsrc/) and
// their licence, and nothing else sits in either vendored tree.
func TestVendoredFilesMatchManifest(t *testing.T) {
	t.Parallel()
	manifest, err := os.ReadFile("vendor.sha256")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(manifest))
	for sc.Scan() {
		sum, name, ok := strings.Cut(sc.Text(), "  ")
		if !ok {
			t.Fatalf("bad manifest line %q", sc.Text())
		}
		want[vendoredPath(name)] = sum
	}
	got := map[string]string{}
	for _, tree := range []struct {
		fsys embed.FS
		root string
	}{{staticFS, "static/vendor"}, {iconFS, "iconsrc"}} {
		err = fs.WalkDir(tree.fsys, tree.root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := tree.fsys.ReadFile(p)
			sum := sha256.Sum256(b)
			got[p] = hex.EncodeToString(sum[:])
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(got) != len(want) {
		t.Errorf("vendor tree has %d files, manifest %d", len(got), len(want))
	}
	for p, sum := range want {
		if got[p] != sum {
			t.Errorf("%s: sha256 %s, manifest %s", p, got[p], sum)
		}
	}
	for _, must := range []string{"static/vendor/novnc-1.7.0/LICENSE.txt", "static/vendor/novnc-1.7.0/docs/LICENSE.MPL-2.0",
		"static/vendor/novnc-1.7.0/core/rfb.js", "static/vendor/novnc-1.7.0/vendor/pako/LICENSE",
		"static/vendor/xterm-6.0.0/LICENSE", "static/vendor/xterm-6.0.0/xterm.mjs", "static/vendor/xterm-6.0.0/xterm.css",
		"static/vendor/xterm-addon-fit-0.11.0/LICENSE", "static/vendor/xterm-addon-fit-0.11.0/addon-fit.mjs",
		"static/vendor/fonts/inter-4.1/inter-var-latin.woff2", "static/vendor/fonts/inter-4.1/OFL.txt",
		"static/vendor/fonts/jetbrains-mono-2.304/jetbrains-mono-var-latin.woff2", "static/vendor/fonts/jetbrains-mono-2.304/OFL.txt",
		"static/vendor/lucide-1.53.0/LICENSE", "iconsrc/lucide-1.53.0/icons/power.svg"} {
		if _, ok := got[must]; !ok {
			t.Errorf("%s missing", must)
		}
	}
}

// vendoredPath maps a manifest name to its embedded path: the Lucide icon sources sit
// in the unserved iconsrc tree (sprite.go), everything else under static/vendor.
func vendoredPath(name string) string {
	if strings.HasPrefix(name, "lucide-1.53.0/icons/") {
		return "iconsrc/" + name
	}
	return "static/vendor/" + name
}

func TestConsoleAssetsAreServedAsModules(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t)
	for _, p := range []string{"/static/console.js", "/static/vendor/novnc-1.7.0/core/rfb.js", "/static/console.css"} {
		rec := c.get(p)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", p, rec.Code)
		}
		ct := rec.Header().Get("Content-Type")
		if strings.HasSuffix(p, ".js") && !strings.HasPrefix(ct, "text/javascript") {
			t.Errorf("%s: Content-Type %q (module scripts need a JavaScript type)", p, ct)
		}
	}
	js := c.get("/static/console.js").Body.String()
	for _, banned := range []string{"eval(", "new Function", "innerHTML", "setAttribute('style'", "password"} {
		if strings.Contains(js, banned) {
			t.Errorf("console.js contains %q", banned)
		}
	}
}

func TestSerialAssetsAreServedAsModules(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t)
	for _, p := range []string{"/static/serial.js", "/static/vendor/xterm-6.0.0/xterm.mjs",
		"/static/vendor/xterm-addon-fit-0.11.0/addon-fit.mjs", "/static/serial.css", "/static/vendor/xterm-6.0.0/xterm.css"} {
		rec := c.get(p)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", p, rec.Code)
		}
		ct := rec.Header().Get("Content-Type")
		if strings.HasSuffix(p, "js") && !strings.HasPrefix(ct, "text/javascript") {
			t.Errorf("%s: Content-Type %q (module scripts need a JavaScript type)", p, ct)
		}
	}
	js := c.get("/static/serial.js").Body.String()
	for _, banned := range []string{"eval(", "new Function", "innerHTML", "setAttribute('style'", "password", "document.write"} {
		if strings.Contains(js, banned) {
			t.Errorf("serial.js contains %q", banned)
		}
	}
	// The palette that CSP keeps xterm.js from injecting is in the static sheet.
	css := c.get("/static/serial.css").Body.String()
	for _, rule := range []string{".xterm-fg-255 {", ".xterm-bg-0 {", ".xterm-rows span { display: inline-block"} {
		if !strings.Contains(css, rule) {
			t.Errorf("serial.css lacks %q", rule)
		}
	}
}

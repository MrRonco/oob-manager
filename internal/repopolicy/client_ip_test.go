package repopolicy

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// forwardingHeader matches the names of the client-address headers a proxy sets.
// Case-insensitive: Go code may spell a header in any case.
var forwardingHeader = regexp.MustCompile("(?i)x-forwarded-for|x-real-ip|realip|[\"`]forwarded[\"`]|forwarded-for|" +
	"cf-connecting-ip|true-client-ip|x-client-ip")

// forwardingHeaderUses returns "path:line: text" for every line that names one.
func forwardingHeaderUses(rel, src string) []string {
	var out []string
	for i, line := range strings.Split(src, "\n") {
		if forwardingHeader.MatchString(line) {
			out = append(out, rel+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
		}
	}
	return out
}

// TestClientIPOnlyFromRemoteAddr: there is no trusted proxy, so a client address comes
// only from the TCP peer (http.Request.RemoteAddr, via clientIP in internal/web/ui).
// Shipped Go code must never read X-Forwarded-For, X-Real-IP, Forwarded, CF-Connecting-IP,
// True-Client-IP or X-Client-IP, nor use a
// RealIP middleware: any client could set them and dodge the per-IP limits and audit.
func TestClientIPOnlyFromRemoteAddr(t *testing.T) {
	var bad []string
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			b, err := os.ReadFile(p) // #nosec G304 G122 -- a test walking the repository's own sources
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			bad = append(bad, forwardingHeaderUses(filepath.ToSlash(rel), string(b))...)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, b := range bad {
		t.Errorf("%s\n\tclient addresses come only from RemoteAddr (clientIP in internal/web/ui); "+
			"forwarding headers are spoofable and must not be read", b)
	}
}

func TestForwardingHeaderUses(t *testing.T) {
	src := "a := r.Header.Get(\"X-Forwarded-For\")\nb := r.RemoteAddr\nc := h.Get(\"x-real-ip\")\n" +
		"r.Header.Get(\"Forwarded\")\nmiddleware.RealIP\n// forwarding headers are ignored\n" +
		"r.Header.Get(\"CF-Connecting-IP\")\nh.Get(`True-Client-IP`)\nh.Get(\"x-client-ip\")\nh.Get(`Forwarded`)\n"
	got := forwardingHeaderUses("x.go", src)
	want := []string{`x.go:1: a := r.Header.Get("X-Forwarded-For")`, `x.go:3: c := h.Get("x-real-ip")`,
		`x.go:4: r.Header.Get("Forwarded")`, "x.go:5: middleware.RealIP",
		`x.go:7: r.Header.Get("CF-Connecting-IP")`, "x.go:8: h.Get(`True-Client-IP`)", `x.go:9: h.Get("x-client-ip")`,
		"x.go:10: h.Get(`Forwarded`)"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

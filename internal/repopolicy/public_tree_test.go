package repopolicy

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The project is public (CLAUDE.md rule 12): no file may carry a detail of somebody's
// network. These rules are GENERIC on purpose. They name no person, host or domain: a
// denylist of real identifiers in a public tree would itself be the leak. The maintainer's
// own identifiers are checked outside the repository by scripts/public-cut.sh.
//
// A file that needs one of these patterns on purpose (a test of the private-address
// policy, the Unraid template's appdata path) opts in with a line that names the rule
// and gives a reason:
//
//	repopolicy:allow <rule> -- <reason of at least a few words>
//
// Documentation examples use 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737),
// 2001:db8::/32 (RFC 3849), MAC addresses 00:00:5E:00:53:xx (RFC 7042) and the
// .example / .test / .invalid names (RFC 2606).

const (
	rulePrivateAddr = "private-addresses"
	ruleHostPaths   = "host-paths"
	ruleHomeNames   = "home-names"
	ruleMAC         = "mac-addresses"
)

type treeRule struct {
	name string
	find func(line string) []string // offending substrings in one line
}

var (
	privateIPv4 = regexp.MustCompile(`\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b`)
	// The RFC 1918 blocks themselves may be named anywhere (they describe the policy).
	rfc1918Blocks = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	hostPath      = regexp.MustCompile(`/mnt/|/boot/config|(?i:\bappdata\b)`)
	macAddr       = regexp.MustCompile(`[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}`)
	homeName      = regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(home\.arpa|lan|home|local)\b`)
	allowMarker   = regexp.MustCompile(`repopolicy:allow ([a-z-]+) -- (.+)`)
)

func findPrivateAddrs(line string) []string {
	var out []string
	for _, m := range privateIPv4.FindAllString(line, -1) {
		if !slices.Contains(rfc1918Blocks, m) {
			out = append(out, m)
		}
	}
	return out
}

func findHostPaths(line string) []string { return hostPath.FindAllString(line, -1) }

// findMACs reports six-octet hex runs that are not the RFC 7042 documentation range
// (00:00:5E:00:53:xx), all zeros or all ones. A run inside a longer colon-separated hex
// string (a fingerprint, an IPv6 address) is not a MAC address.
func findMACs(line string) []string {
	var out []string
	for _, loc := range macAddr.FindAllStringIndex(line, -1) {
		if adjacentHex(line, loc[0], loc[1]) {
			continue
		}
		m := strings.ToUpper(strings.ReplaceAll(line[loc[0]:loc[1]], "-", ":"))
		if strings.HasPrefix(m, "00:00:5E:00:53:") || m == "00:00:00:00:00:00" || m == "FF:FF:FF:FF:FF:FF" {
			continue
		}
		out = append(out, line[loc[0]:loc[1]])
	}
	return out
}

func adjacentHex(line string, start, end int) bool {
	isSep := func(b byte) bool { return b == ':' || b == '-' }
	isHex := func(b byte) bool {
		return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
	}
	before := start > 0 && (isHex(line[start-1]) || (isSep(line[start-1]) && start > 1 && isHex(line[start-2])))
	after := end < len(line) && (isHex(line[end]) || (isSep(line[end]) && end+1 < len(line) && isHex(line[end+1])))
	return before || after
}

// findHomeNames reports host names under the TLDs home networks use (.lan, .home,
// .local, .home.arpa). "x.Local" in title case is a Go selector (xml.Name.Local), and a
// name followed by more of a word (".localhost", "config.local.yaml") is not one.
func findHomeNames(line string) []string {
	var out []string
	for _, loc := range homeName.FindAllStringSubmatchIndex(line, -1) {
		tld := line[loc[2]:loc[3]]
		if tld == "Local" {
			continue
		}
		if end := loc[1]; end+1 < len(line) && line[end] == '.' && isWordByte(line[end+1]) {
			continue
		}
		out = append(out, line[loc[0]:loc[1]])
	}
	return out
}

func isWordByte(b byte) bool {
	return b == '_' || b == '-' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func publicTreeRules() []treeRule {
	return []treeRule{
		{rulePrivateAddr, findPrivateAddrs},
		{ruleHostPaths, findHostPaths},
		{ruleMAC, findMACs},
		{ruleHomeNames, findHomeNames},
	}
}

// skippedDirs are not ours to police (third-party code, generated output) or not text.
var skippedDirs = []string{
	".git", "node_modules", "bin",
	"internal/web/ui/static/vendor", // vendored third-party assets, checked by vendor.sha256
	"tests/e2e/test-results", "tests/e2e/playwright-report", "tests/zap/reports",
}

// allowances returns the rules a file opts out of, and the markers that are malformed
// (no reason, unknown rule).
func allowances(text string) (map[string]bool, []string) {
	allowed := map[string]bool{}
	var bad []string
	known := []string{rulePrivateAddr, ruleHostPaths, ruleHomeNames, ruleMAC}
	for _, m := range allowMarker.FindAllStringSubmatch(text, -1) {
		reason := strings.TrimSpace(strings.TrimRight(strings.TrimSpace(m[2]), "-?*/>"))
		switch {
		case !slices.Contains(known, m[1]):
			bad = append(bad, fmt.Sprintf("unknown rule %q in marker", m[1]))
		case len(strings.Fields(reason)) < 3:
			bad = append(bad, fmt.Sprintf("marker for %q needs a reason of a few words", m[1]))
		default:
			allowed[m[1]] = true
		}
	}
	return allowed, bad
}

// treeProblems checks one file's text against every rule it has not opted out of.
func treeProblems(rel, text string) []string {
	allowed, problems := allowances(text)
	for i, line := range strings.Split(text, "\n") {
		for _, r := range publicTreeRules() {
			if allowed[r.name] {
				continue
			}
			for _, hit := range r.find(line) {
				problems = append(problems, fmt.Sprintf("%s:%d: %s %q", rel, i+1, r.name, hit))
			}
		}
	}
	return problems
}

func isTextFile(b []byte) bool {
	return !bytes.Contains(b[:min(len(b), 8000)], []byte{0})
}

// TestPublicTreeHasNoNetworkDetails walks the whole tree (it also runs on the exported
// cut, which has no .git) and fails on any private address, host path, real-looking MAC
// address or home-network host name outside an opted-in file.
func TestPublicTreeHasNoNetworkDetails(t *testing.T) {
	self := filepath.Join("internal", "repopolicy", "public_tree_test.go")
	var problems []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if slices.Contains(skippedDirs, filepath.ToSlash(rel)) || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if rel == self || !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(path) // #nosec G304 G122 -- a test walking the repository's own files
		if err != nil || !isTextFile(b) {
			return err
		}
		problems = append(problems, treeProblems(filepath.ToSlash(rel), string(b))...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

func TestTreeRules(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"bmc: { address: 192.0.2.10 }  # TEST-NET-1", nil},
		{"egress from 198.51.100.7 and 203.0.113.9, v6 2001:db8::1", nil},
		{"bmc_networks: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]", nil},
		{"address: 10.1.2.3", []string{"private-addresses \"10.1.2.3\""}},
		{"lan 192.168.1.0/24 and 172.20.0.5", []string{"private-addresses \"192.168.1.0/24\"", "private-addresses \"172.20.0.5\""}},
		{"not private: 172.32.0.1, 100.10.1.1, 110.0.0.1", nil},
		{"volume /mnt/user/x and /boot/config/go, AppData", []string{"host-paths \"/mnt/\"", "host-paths \"/boot/config\"", "host-paths \"AppData\""}},
		{"MAC 00:00:5E:00:53:2a and 00-00-5e-00-53-01 and 00:00:00:00:00:00", nil},
		{"MAC 02:00:00:aa:bb:cc (locally administered, fake)", []string{"mac-addresses \"02:00:00:aa:bb:cc\""}},
		{"fingerprint aa:bb:cc:dd:ee:ff:00:11:22 and fe80::1:2:3:4", nil},
		{"https://oob.home.arpa/ and nas.lan, box.local.", []string{"home-names \"oob.home.arpa\"", "home-names \"nas.lan\"", "home-names \"box.local\""}},
		{"t.Name.Local, localhost, a.localdomain, config.local.yaml, oob.example", nil},
		{"REDACTED.BOX.LOCAL", []string{"home-names \"REDACTED.BOX.LOCAL\""}},
	}
	for _, c := range cases {
		var got []string
		for _, r := range publicTreeRules() {
			for _, hit := range r.find(c.line) {
				got = append(got, fmt.Sprintf("%s %q", r.name, hit))
			}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%q: got %v, want %v", c.line, got, c.want)
		}
	}
}

func TestAllowMarkers(t *testing.T) {
	text := "// repopolicy:allow private-addresses -- tests the RFC 1918 egress policy\nx := \"10.1.2.3\"\n/mnt/x\n"
	got := treeProblems("a_test.go", text)
	if want := []string{`a_test.go:3: host-paths "/mnt/"`}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	_, bad := allowances("<!-- repopolicy:allow host-paths -- ok -->\n# repopolicy:allow everything -- because I said so\n")
	if len(bad) != 2 {
		t.Errorf("malformed markers = %v, want 2 (short reason, unknown rule)", bad)
	}
	if allowed, _ := allowances("<!-- repopolicy:allow host-paths -- the Unraid template's appdata path -->"); !allowed[ruleHostPaths] {
		t.Error("an HTML comment marker with a reason is not honoured")
	}
}

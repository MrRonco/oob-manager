package ui

import (
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"oob-manager/internal/authz"
)

// TestGoLinksFirmwareByRole: with the firmware view wired, every role that may see it
// (viewer, operator, admin) gets /firmware, as in the sidebar; only the admin gets Settings.
func TestGoLinksFirmwareByRole(t *testing.T) {
	e := newFWEnv(t)
	for i, role := range []authz.Role{authz.RoleViewer, authz.RoleOperator} {
		c := e.userClient(t, "u"+string(role), role, "192.0.2."+string(rune('6'+i))+"0")
		list := goList(t, c, "/go")
		if !strings.Contains(list, `href="/firmware"`) {
			t.Errorf("%s: no /firmware with the firmware view on", role)
		}
		if strings.Contains(list, `href="/settings`) {
			t.Errorf("%s: sees a Settings path", role)
		}
	}
	admin := goList(t, e.adminClient(), "/go")
	for _, want := range []string{`href="/firmware"`, `href="/settings"`, `href="/settings/audit"`} {
		if !strings.Contains(admin, want) {
			t.Errorf("admin's list lacks %s", want)
		}
	}
}

var hrefRE = regexp.MustCompile(`<a href="([^"]+)"`)

func hrefsIn(s string) []string {
	var out []string
	for _, m := range hrefRE.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// TestGoLinksMatchTheSidebar: the Pages and Servers groups hold exactly the sidebar's links,
// in its order, for each role, with and without the firmware view.
func TestGoLinksMatchTheSidebar(t *testing.T) {
	e := newFWEnv(t)
	plain, plainC := goClient(t, authz.RoleViewer)
	_ = plain
	clients := map[string]*client{"viewer, no firmware": plainC, "admin, firmware": e.adminClient(),
		"operator, firmware": e.userClient(t, "olga", authz.RoleOperator, "192.0.2.80")}
	for name, c := range clients {
		page := result(c.get("/activity")).status(t, http.StatusOK).rec.Body.String()
		side := hrefsIn(between(page, `<aside class="side"`, "</aside>"))
		tpl := between(page, `<template id="oob-go">`, "</template>")
		var fromGo []string
		for _, g := range []string{"Pages", "Servers"} {
			fromGo = append(fromGo, hrefsIn(between(tpl, `data-group="`+g+`"`, "</ul>"))...)
		}
		if !slices.Equal(side, fromGo) {
			t.Errorf("%s:\nsidebar %v\nGo to   %v", name, side, fromGo)
		}
	}
}

// TestGoLinksEscapeServerNames: a server name is text everywhere: the /go list, the
// palette's <template> and the hint.
func TestGoLinksEscapeServerNames(t *testing.T) {
	h, c := goClient(t, authz.RoleViewer)
	v := h.fleet.servers[2]
	v.Name = `<img src=x onerror=alert(1)>&"`
	h.fleet.servers[2] = v
	for _, p := range []string{"/go", "/activity"} {
		body := result(c.get(p)).status(t, http.StatusOK).rec.Body.String()
		if strings.Contains(body, "<img src=x") {
			t.Errorf("%s: the name is not escaped", p)
		}
		if !strings.Contains(body, `&lt;img src=x onerror=alert(1)&gt;&amp;&#34;`) {
			t.Errorf("%s: the escaped name is missing", p)
		}
	}
}

// TestPalettePathPatternAcceptsEveryServerID: palette.js drops any path outside PATH_RE, so
// every server ID the registry accepts (config idPattern: ^[a-z0-9][a-z0-9-]{0,31}$) and every
// path of the destination list must pass it. The pattern is read from the script itself.
func TestPalettePathPatternAcceptsEveryServerID(t *testing.T) {
	b, err := os.ReadFile("static/palette.js")
	must(t, err)
	m := regexp.MustCompile(`var PATH_RE = /(.+)/;`).FindSubmatch(b)
	if m == nil {
		t.Fatal("PATH_RE not found")
	}
	re := regexp.MustCompile(strings.ReplaceAll(string(m[1]), `\/`, `/`))
	ids := []string{"a", "0", "r730xd", "edge-1", strings.Repeat("z", 32), "a-b-c-9"}
	for _, id := range ids {
		for _, p := range []string{"/servers/" + id, "/servers/" + id + "/sensors", "/settings/servers/" + id} {
			if !re.MatchString(p) {
				t.Errorf("PATH_RE refuses %s", p)
			}
		}
	}
	for _, g := range (layoutData{User: "u", IsAdmin: true, CanLogs: true, CanFirmware: true}).GoLinks() {
		for _, l := range g.Links {
			if !re.MatchString(l.Href) {
				t.Errorf("PATH_RE refuses the destination %s", l.Href)
			}
		}
	}
	for _, bad := range []string{"//evil.example", "/x?y=1", "/x#y", "https://evil.example/", "/a//b", "/a/", "javascript:x",
		"/servers/r240/../../settings/users", "/a/./b", "/..", "/.", "/servers/r240/.."} {
		if re.MatchString(bad) {
			t.Errorf("PATH_RE accepts %q", bad)
		}
	}
}

func TestParseGoQueryJoiners(t *testing.T) {
	for _, ok := range []string{"a\u200db", "a\u200cb"} { // ZWJ (emoji, Indic), ZWNJ (Persian)
		if got, accepted := parseGoQuery(ok); !accepted || got != ok {
			t.Errorf("parseGoQuery(%q) = %q, %v", ok, got, accepted)
		}
	}
	for _, bad := range []string{"a\u202eb", "a\u2066b", "a\u200eb", "a\ufeffb", "a\u00adb"} { // bidi, BOM, soft hyphen
		if _, accepted := parseGoQuery(bad); accepted {
			t.Errorf("parseGoQuery(%q) accepted", bad)
		}
	}
}

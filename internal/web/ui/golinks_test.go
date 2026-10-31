package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"oob-manager/internal/authz"
)

// goClient signs in a user of role on a fresh harness.
func goClient(t *testing.T, role authz.Role) (*harness, *client) {
	t.Helper()
	h := newHarness(t)
	secret := h.addUser("pat", role, true)
	c := h.client("192.0.2.40")
	c.login("pat", secret)
	return h, c
}

// goList is the server-rendered destination list of the /go page.
func goList(t *testing.T, c *client, path string) string {
	t.Helper()
	return between(result(c.get(path)).status(t, http.StatusOK).rec.Body.String(), `<div class="golist">`, `id="shortcuts"`)
}

func TestGoPageRequiresSession(t *testing.T) {
	h := newHarness(t)
	result(h.client("192.0.2.41").get("/go")).status(t, http.StatusSeeOther).location(t, "/login")
}

// TestGoPageViewerSeesOnlyWhatTheSidebarShows: a viewer gets the pages, the servers and the
// account links, never Settings or a settings tab. This harness has no firmware view, so
// nobody gets /firmware here; TestGoLinksFirmwareByRole wires it for every role.
func TestGoPageViewerSeesOnlyWhatTheSidebarShows(t *testing.T) {
	_, c := goClient(t, authz.RoleViewer)
	list := goList(t, c, "/go")
	for _, want := range []string{`href="/"`, `href="/servers"`, `href="/events"`, `href="/activity"`, `href="/help"`,
		`href="/servers/r730xd"`, `href="/servers/r240"`, `href="/servers/spare"`, "Spare box",
		`href="/preferences"`, `href="/about"`} {
		if !strings.Contains(list, want) {
			t.Errorf("viewer's list lacks %s", want)
		}
	}
	for _, bad := range []string{`href="/settings`, `href="/firmware"`} {
		if strings.Contains(list, bad) {
			t.Errorf("viewer's list shows %s", bad)
		}
	}
}

func TestGoPageAdminSeesSettings(t *testing.T) {
	_, c := goClient(t, authz.RoleAdmin)
	list := goList(t, c, "/go")
	for _, l := range settingsLinks() {
		if !strings.Contains(list, `href="`+l.Href+`"`) {
			t.Errorf("admin's list lacks %s", l.Href)
		}
	}
	if !strings.Contains(list, `href="/settings"`) {
		t.Error("admin's list lacks Settings")
	}
}

// TestGoPageWorksWithoutScript: the list, a GET filter with a label and the shortcut
// table are plain HTML; the script-only toggle is hidden until palette.js shows it.
func TestGoPageWorksWithoutScript(t *testing.T) {
	_, c := goClient(t, authz.RoleViewer)
	result(c.get("/go")).status(t, http.StatusOK).contains(t,
		"<h1>Go to</h1>", `<form class="filters panel" method="get" action="/go" role="search">`,
		`<label for="go-q">`, `id="go-q" name="q" type="search"`, `id="shortcuts"`, "<kbd>Ctrl</kbd>",
		`id="sc-toggle" hidden`, `<title>Go to · oob-manager</title>`).
		lacks(t, `aria-current="page"`+">", "<noscript><meta")
}

func TestGoPageFilters(t *testing.T) {
	_, c := goClient(t, authz.RoleViewer)
	list := goList(t, c, "/go?q="+url.QueryEscape("  SPARE "))
	if !strings.Contains(list, `href="/servers/spare"`) || strings.Contains(list, `href="/servers/r730xd"`) ||
		strings.Contains(list, `href="/events"`) {
		t.Errorf("q=spare list:\n%s", list)
	}
	result(c.get("/go?q=spare")).contains(t, `value="spare"`, "1 of ")
	// Every word must match, in the label, the hint or the group.
	list = goList(t, c, "/go?q="+url.QueryEscape("account display"))
	if !strings.Contains(list, `href="/preferences"`) || strings.Contains(list, `href="/about"`) {
		t.Errorf("q=account display list:\n%s", list)
	}
	result(c.get("/go?q=nothing-matches")).status(t, http.StatusOK).contains(t, "Nothing matches")
}

func TestGoPageRejectsBadFilter(t *testing.T) {
	_, c := goClient(t, authz.RoleViewer)
	result(c.get("/go?q="+strings.Repeat("a", maxGoQuery+1))).status(t, http.StatusBadRequest)
	result(c.get("/go?q="+url.QueryEscape("a\x00b"))).status(t, http.StatusBadRequest)
	result(c.get("/go?q="+url.QueryEscape(`"><script>`))).status(t, http.StatusOK).
		lacks(t, `"><script>`).contains(t, `value="&#34;&gt;&lt;script&gt;"`)
}

func TestFilterGoKeepsGroupsImmutable(t *testing.T) {
	all := []goGroup{{ID: "a", Label: "Pages", Links: []goLink{{"Overview", "", "/"}, {"Help", "", "/help"}}}}
	got := filterGo(all, "help")
	if len(got) != 1 || len(got[0].Links) != 1 || got[0].Links[0].Href != "/help" {
		t.Fatalf("filter: %+v", got)
	}
	if len(all[0].Links) != 2 {
		t.Fatal("filterGo changed its input")
	}
	if got := filterGo(all, "pages overview"); len(got) != 1 || got[0].Links[0].Href != "/" {
		t.Fatalf("group label match: %+v", got)
	}
	if got := filterGo(all, "zzz"); len(got) != 0 {
		t.Fatalf("no match: %+v", got)
	}
	if got := filterGo(all, " "); len(got) != 1 || len(got[0].Links) != 2 {
		t.Fatalf("blank query: %+v", got)
	}
}

// TestLayoutCarriesThePaletteOnlyWhenSignedIn: a signed-in page loads palette.js (deferred,
// from 'self') and the inert destination list; the sign-in page has neither.
func TestLayoutCarriesThePaletteOnlyWhenSignedIn(t *testing.T) {
	h, c := goClient(t, authz.RoleViewer)
	page := result(c.get("/events")).status(t, http.StatusOK)
	page.contains(t, `<script src="/static/palette.js?v=dev" defer></script>`, `<template id="oob-go">`,
		`href="/go" data-palette`)
	tpl := between(page.rec.Body.String(), `<template id="oob-go">`, "</template>")
	if !strings.Contains(tpl, `href="/servers/r240"`) || strings.Contains(tpl, `href="/settings`) {
		t.Errorf("viewer's palette list:\n%s", tpl)
	}
	result(h.client("192.0.2.42").get("/login")).lacks(t, "palette.js", "oob-go", "oob-recent")
}

// TestRecentMarksOnlyPlainViews: palette.js may remember a signed-in GET view answered
// 200, never an error, the Go to page itself, a confirm page or a pre-session page.
func TestRecentMarksOnlyPlainViews(t *testing.T) {
	h, c := goClient(t, authz.RoleAdmin)
	const mark = `<meta name="oob-recent" content="on">`
	for _, p := range []string{"/", "/servers/r730xd", "/events", "/servers", "/activity", "/help"} {
		result(c.get(p)).status(t, http.StatusOK).contains(t, mark)
	}
	for p, status := range map[string]int{"/go": http.StatusOK, "/servers/nope": http.StatusNotFound,
		"/go?q=" + strings.Repeat("x", maxGoQuery+1): http.StatusBadRequest} {
		if rec := result(c.get(p)).status(t, status); strings.Contains(rec.rec.Body.String(), mark) {
			t.Errorf("%s is marked recent", p)
		}
	}
	anon := h.client("192.0.2.43")
	for _, p := range []string{"/login", "/help"} {
		result(anon.get(p)).lacks(t, mark)
	}
}

func TestPaletteScriptIsServedAndPlain(t *testing.T) {
	_, c := signedIn(t)
	rec := result(c.get("/static/palette.js")).status(t, http.StatusOK)
	if ct := rec.rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("Content-Type %q", ct)
	}
	for _, banned := range []string{"eval(", "new Function", "innerHTML", "outerHTML", "insertAdjacentHTML",
		"document.write", "setAttribute('style'", ".style.",
		"fetch(", "XMLHttpRequest", ".submit(", "requestSubmit", "location.search"} {
		if strings.Contains(rec.rec.Body.String(), banned) {
			t.Errorf("palette.js contains %q", banned)
		}
	}
	for _, must := range []string{"'use strict'", "sessionStorage", "aria-modal", "showModal", "try {"} {
		if !strings.Contains(rec.rec.Body.String(), must) {
			t.Errorf("palette.js lacks %q", must)
		}
	}
}

func TestRecentOKNeedsAPlainSignedInGET(t *testing.T) {
	get := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", nil)
	post := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", nil)
	user := layoutData{User: "pat"}
	if !recentOK(get, http.StatusOK, pageServer, user) {
		t.Fatal("a server page is a recent page")
	}
	for name, ok := range map[string]bool{
		"post":     recentOK(post, http.StatusOK, pageServer, user),
		"status":   recentOK(get, http.StatusBadRequest, pageServer, user),
		"anon":     recentOK(get, http.StatusOK, pageServer, layoutData{}),
		"confirm":  recentOK(get, http.StatusOK, pageConfirm, user),
		"reveal":   recentOK(get, http.StatusOK, pageSettingsReveal, user),
		"stepup":   recentOK(get, http.StatusOK, pageStepUp, user),
		"console":  recentOK(get, http.StatusOK, pageConsole, user),
		"serial":   recentOK(get, http.StatusOK, pageSerial, user),
		"go":       recentOK(get, http.StatusOK, pageGo, user),
		"error":    recentOK(get, http.StatusOK, pageError, user),
		"enroll":   recentOK(get, http.StatusOK, pageEnrolLink, user),
		"new-item": recentOK(get, http.StatusOK, pageSettingsServerNew, user),
	} {
		if ok {
			t.Errorf("%s: remembered as recent", name)
		}
	}
}

func TestParseGoQuery(t *testing.T) {
	for raw, want := range map[string]string{"  a\u00a0b\t c ": "a b c", "": "", strings.Repeat("é", maxGoQuery): strings.Repeat("é", maxGoQuery)} {
		if got, ok := parseGoQuery(raw); !ok || got != want {
			t.Errorf("parseGoQuery(%q) = %q, %v; want %q", raw, got, ok, want)
		}
	}
	for _, raw := range []string{strings.Repeat("é", maxGoQuery+1), "a\x00b", "a\u200bb"} {
		if _, ok := parseGoQuery(raw); ok {
			t.Errorf("parseGoQuery(%q) accepted", raw)
		}
	}
}

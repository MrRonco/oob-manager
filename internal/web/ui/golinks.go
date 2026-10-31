package ui

import (
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The Go to destinations (plan 04 §7 and §11 item 7, docs/tech_doc.md §52): one list built
// from the signed-in chrome, so it holds exactly what the sidebar and the account menu
// already show to this user (Settings only for an admin, Firmware and Events only when the
// role may see them, servers only with fleet.view). The /go page renders it server-side
// (the no-script fallback, with a GET filter), and the layout carries the same list in an
// inert <template> for the optional palette.js, which never adds a destination of its own
// beyond the current page's tabs and the recent pages it saw.

// navGo is the /go page's nav value: no sidebar item is current.
const navGo = "go"

// maxGoQuery bounds the /go filter (the events filter's limit).
const maxGoQuery = 64

// goLink is one destination: a same-origin path, its label and a muted hint.
type goLink struct{ Label, Hint, Href string }

// goGroup is one heading of the list. ID is a stable token for element ids.
type goGroup struct {
	ID, Label string
	Links     []goLink
}

// settingsLinks returns the Settings tabs in their partial's order (templates/partials.html
// "settingstabs"), a fresh slice each call; every one of them needs the admin role.
func settingsLinks() []goLink {
	return []goLink{
		{"Users", "Settings", "/settings/users"},
		{"API tokens", "Settings", "/settings/tokens"},
		{"General", "Settings", "/settings/general"},
		{"Servers", "Settings", "/settings/servers"},
		{"Notifications", "Settings", "/settings/notifications"},
		{"Integrations", "Settings", "/settings/integrations"},
		{"Audit log", "Settings", "/settings/audit"},
	}
}

// GoLinks is every destination of this page's user, in the sidebar's order. It reads only
// the fields layoutFor filled from authz, so a page without a user has none.
func (d layoutData) GoLinks() []goGroup {
	if d.User == "" {
		return nil
	}
	pages := []goLink{{"Overview", "", "/"}, {"Servers", "Every server", "/servers"}}
	if d.CanFirmware {
		pages = append(pages, goLink{"Firmware", "Every component", "/firmware"})
	}
	if d.CanLogs {
		pages = append(pages, goLink{"Events", "Every server's logs", "/events"})
	}
	pages = append(pages, goLink{"Activity", "What was done to the servers", "/activity"})
	if d.IsAdmin {
		pages = append(pages, goLink{"Settings", "", "/settings"})
	}
	pages = append(pages, goLink{"Help", "", "/help"})
	groups := []goGroup{{ID: "pages", Label: "Pages", Links: pages}}
	if servers := serverLinks(d.Servers); len(servers) > 0 {
		groups = append(groups, goGroup{ID: "servers", Label: "Servers", Links: servers})
	}
	if d.IsAdmin {
		groups = append(groups, goGroup{ID: "settings", Label: "Settings", Links: settingsLinks()})
	}
	return append(groups, goGroup{ID: "account", Label: "Account", Links: []goLink{
		{"Display preferences", "Time zone, theme, units", "/preferences"},
		{"About and licenses", "", "/about"},
	}})
}

// serverLinks are the sidebar's servers, with its sub-line (which names a maintenance window)
// and the state as the hint.
func serverLinks(entries []navEntry) []goLink {
	out := make([]goLink, 0, len(entries))
	for _, e := range entries {
		hint := make([]string, 0, 3)
		if e.Value != "" {
			hint = append(hint, e.Value)
		}
		// The state, unless the sub-line already says it ("No data", "Stale · 10 min").
		if first, _, _ := strings.Cut(e.Value, " "); e.Health.Label != "" && (e.Value == "" || !strings.HasPrefix(e.Health.Label, first)) {
			hint = append(hint, e.Health.Label)
		}
		out = append(out, goLink{Label: e.Name, Hint: strings.Join(hint, " · "), Href: "/servers/" + e.ID})
	}
	return out
}

// filterGo keeps the links whose label, hint or group holds every word of q (case
// insensitive), and drops groups left empty. palette.js matches the same way.
func filterGo(groups []goGroup, q string) []goGroup {
	words := strings.Fields(strings.ToLower(q))
	if len(words) == 0 {
		return groups
	}
	out := make([]goGroup, 0, len(groups))
	for _, g := range groups {
		var links []goLink
		for _, l := range g.Links {
			if matchesAll(strings.ToLower(l.Label+" "+l.Hint+" "+g.Label), words) {
				links = append(links, l)
			}
		}
		if len(links) > 0 {
			out = append(out, goGroup{ID: g.ID, Label: g.Label, Links: links})
		}
	}
	return out
}

func matchesAll(text string, words []string) bool {
	for _, w := range words {
		if !strings.Contains(text, w) {
			return false
		}
	}
	return true
}

func countLinks(groups []goGroup) int {
	n := 0
	for _, g := range groups {
		n += len(g.Links)
	}
	return n
}

// goView is the /go page.
type goView struct {
	Query  string
	Groups []goGroup
	Shown  int
	Total  int
}

// goPage is the no-script Go to page: every destination of the user, a GET filter and the
// keyboard shortcuts of palette.js (#shortcuts).
func (s *server) goPage(w http.ResponseWriter, r *http.Request, sess session) {
	q, ok := parseGoQuery(r.URL.Query().Get("q"))
	if !ok {
		s.errorPage(w, r, http.StatusBadRequest, "The filter is too long or holds characters it cannot use.")
		return
	}
	d := s.layoutFor(sess, "Go to", navGo, nil)
	all := d.GoLinks()
	shown := filterGo(all, q)
	d.Body = goView{Query: q, Groups: shown, Shown: countLinks(shown), Total: countLinks(all)}
	s.render(w, r, http.StatusOK, pageGo, d)
}

// recentPage reports whether palette.js may remember page as recent (layoutData.Recent): plain
// GET views a user may want to reopen. Never a sign-in, enrollment, setup, step-up, confirm,
// reveal (a shown-once secret), error or console page, or a form for a new item.
func recentPage(page string) bool {
	switch page {
	case pageOverview, pageServers, pageServer, pageSensors, pageLogs, pageSrvActivity, pageActivity, pageInventory,
		pageEvents, pageAbout, pageHelp, pageSecurity, pageFirmware, pageHistory, pageFan, pageSettingsUsers,
		pageSettingsUser, pageSettingsTokens, pageSettingsAudit, pageSettingsGeneral, pageDisplay, pageSettingsServers,
		pageSettingsServer, pageSettingsNotify, pageSettingsIntegrations:
		return true
	}
	return false
}

// recentOK reports whether this response may be remembered as a recent page: a signed-in
// GET answered 200 with one of the recentPage pages.
func recentOK(r *http.Request, status int, page string, d layoutData) bool {
	return r.Method == http.MethodGet && status == http.StatusOK && d.User != "" && recentPage(page)
}

// parseGoQuery normalises the /go filter: any Unicode space (a pasted no-break space too)
// becomes one ASCII space, the ends are trimmed. It refuses more than maxGoQuery
// characters (the field's maxlength counts characters, not bytes) and any other
// non-printable character except the two joiners that are part of written words and emoji
// (goQueryRune): bidi overrides and isolates, direction marks, the BOM and the soft hyphen
// stay out.
func parseGoQuery(raw string) (string, bool) {
	q := strings.Join(strings.FieldsFunc(raw, unicode.IsSpace), " ")
	if utf8.RuneCountInString(q) > maxGoQuery || strings.ContainsFunc(q, func(c rune) bool { return !goQueryRune(c) }) {
		return "", false
	}
	return q, true
}

// Zero-width non-joiner (Persian, Indic scripts) and zero-width joiner (emoji sequences,
// Indic conjuncts).
const (
	zwnj = '\u200c'
	zwj  = '\u200d'
)

// goQueryRune is a character the /go filter keeps.
func goQueryRune(c rune) bool {
	return unicode.IsPrint(c) || c == zwnj || c == zwj
}

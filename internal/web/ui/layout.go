package ui

import (
	"context"
	"net/http"
	"time"

	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/display"
)

// Top-level navigation items (layoutData.Nav). The current item gets aria-current.
const (
	navOverview = "overview"
	navServers  = "servers"
	navFirmware = "firmware"
	navEvents   = "events"
	navActivity = "activity"
	navSettings = "settings"
	navAbout    = "about"
	navHelp     = "help"
)

// layoutData is what every page receives. Body holds the page-specific view model.
// Direction B shell: a sticky top bar (brand, instance name, fleet pill, clock, user
// menu; a Menu sheet on phones) and, when signed in, a sidebar with the navigation and
// every server with its health.
type layoutData struct {
	Title   string
	User    string // username; "" on pre-session pages (plain shell, no sidebar)
	Role    string
	IsAdmin bool // shows the Settings nav item (the routes enforce authz themselves)
	CanLogs bool // shows the Events nav item
	// CanFirmware shows the Firmware nav item; FirmwareWarn is its count (components below
	// their minimum).
	CanFirmware  bool
	FirmwareWarn int
	LogoutCSRF   string
	Nav          string     // active top-level nav item
	Servers      []navEntry // the sidebar server switcher
	ServerID     string     // the server this page is about, if any (marked current)
	Crumbs       []crumb    // breadcrumb; the last entry is the current page
	Flash        string
	FlashKind    string // "error" or "info"
	Refresh      int    // seconds for <meta http-equiv=refresh>; 0 = off
	// RefreshScriptOnly drops the no-script meta refresh: the page carries typed input,
	// which only the script's refresh (paused while editing) leaves alone.
	RefreshScriptOnly bool
	Footer            footerData
	Instance          string // configured instance name ("" = none)
	Theme             string // "dark", "light" or "" (follow the OS)
	Palette           string // color theme (display.Theme), <html data-palette>
	Density           string // "compact" or "comfortable", <html data-density>
	ThemeForm         themeForm
	Pill              pillView
	Clock             clockView
	Events24h         int // warning and critical events in the last 24 hours (nav count)
	// BodyClass is set on <body> ("has-bottombar": a server page with the phone action bar).
	BodyClass string
	// KeyNotice is the admin banner while generated keys await a backup (plan 09).
	KeyNotice *keyNoticeView
	// Recent lets palette.js remember this page in the tab's recent list (recentOK).
	Recent bool
	// ServerMenus are a server page's actions for the phone bottom bar (nil elsewhere).
	ServerMenus *serverMenus
	Body        any
}

// Favicon names the status favicon for this page: only signed-in pages carry the
// fleet's state; any other page keeps the plain mark ("").
func (d layoutData) Favicon() string {
	if d.User == "" {
		return ""
	}
	return d.Pill.Favicon()
}

// navEntry is one server in the sidebar: status icon, name and one number (the
// hottest temperature, or the data age when it is stale).
type navEntry struct {
	ID, Name string
	Health   healthView
	Value    string
	Maint    string // the maintenance badge text; "" when not in maintenance
}

// crumb is one breadcrumb step; Href "" marks the current page.
type crumb struct{ Label, Href string }

// footerData is the page footer. Version and links are shown to signed-in users only,
// so the login page does not fingerprint the build.
type footerData struct {
	Version   string // "v1.2.3 (abc1234)"
	Asset     string // cache-busting query for static assets (the raw build version)
	RepoURL   string
	Generated string // when this page was rendered (makes a frozen page self-evident)
	ISO       string
}

// layoutFor fills the signed-in chrome: user, role, nav, sidebar, pill, clock, footer.
func (s *server) layoutFor(sess session, title, nav string, body any) layoutData {
	d := s.layoutIn(title, body, sess.view)
	d.Nav, d.User, d.Role = nav, sess.id.User.Username, string(sess.id.User.Role)
	p := sess.id.Principal()
	d.IsAdmin = s.d.Authorize(p, authz.AdminUsers, true) == nil
	if d.IsAdmin {
		d.KeyNotice = s.keyNotice(sess)
	}
	d.CanLogs = s.d.Authorize(p, authz.ViewLogs, true) == nil
	d.LogoutCSRF = s.csrf.issue(formLogout, sessionBinding(sess.token))
	d.ThemeForm = themeForm{CSRF: s.csrf.issue(formPrefs, sessionBinding(sess.token))}
	if s.d.Authorize(p, authz.ViewFleet, true) == nil {
		views := s.d.Fleet.Servers() // never list servers to someone who may not see them
		d.Servers, d.Pill, d.Clock.DataAge = s.chrome(views, sess.view)
		if d.CanLogs {
			d.Events24h = s.recentEventCount(views)
		}
		d.CanFirmware = s.firmwareOn() && s.d.Authorize(p, authz.ViewFirmware, true) == nil
		if d.CanFirmware {
			d.FirmwareWarn = s.d.Firmware.WarnCount(context.Background())
		}
	}
	d.Footer.Version, d.Footer.RepoURL = versionLabel(s.d.Build), s.d.Build.RepoURL
	d.Footer.Asset = s.d.Build.Version // signed-in pages only: the login page must not fingerprint the build
	return d
}

// baseLayout is the chrome of a page without a session: the app's default zone and
// theme (the sign-in page, enrollment links).
func (s *server) baseLayout(r *http.Request, title string, body any) layoutData {
	return s.layoutIn(title, body, s.viewFor(r.Context(), ""))
}

// layoutIn is the chrome every page has, signed in or not, shown with view v.
func (s *server) layoutIn(title string, body any, v display.View) layoutData {
	now, tf := s.d.Now(), fmtFor(v)
	iso := now.UTC().Format(time.RFC3339)
	return layoutData{Title: title, Body: body, Instance: s.instanceName(),
		Palette: string(v.Theme), Density: string(v.Density),
		Clock:  clockView{Time: tf.clockOf(now), ISO: iso, Zone: v.Zone},
		Footer: footerData{Generated: tf.clockOf(now), ISO: iso}}
}

// versionLabel is "v1.2.3 (abc1234)" (UX-25); a dev build shows "dev".
func versionLabel(b Build) string {
	v := b.Version
	if v == "" {
		v = "dev"
	}
	if v != "dev" && v[0] >= '0' && v[0] <= '9' {
		v = "v" + v
	}
	if c := b.Commit; c != "" {
		v += " (" + c[:min(len(c), 7)] + ")"
	}
	return v
}

func (s *server) navServers(vw display.View) []navEntry {
	entries, _, _ := s.chrome(s.d.Fleet.Servers(), vw)
	return entries
}

// serverCrumbs is Overview / Servers / <name> [/ <tab>].
func serverCrumbs(id, name, tab string) []crumb {
	cs := []crumb{{"Overview", "/"}, {"Servers", "/servers"}}
	if tab == "" {
		return append(cs, crumb{Label: name})
	}
	return append(cs, crumb{name, "/servers/" + id}, crumb{Label: tab})
}

// refreshCookie stores the per-browser auto-refresh preference. Auto-refresh is opt-in
// (WCAG 2.2.1: no timed change the user did not ask for); the page stays truthful
// without it because poll times are absolute and the generation time is shown. It
// holds only "on"; absence means off.
const refreshCookie = "__Host-oob_refresh"

func autoRefreshOn(r *http.Request) bool {
	c, err := r.Cookie(refreshCookie)
	return err == nil && c.Value == "on"
}

// withRefresh enables the meta refresh on a live-data page when the user turned it on.
func (s *server) withRefresh(r *http.Request, d layoutData) layoutData {
	if autoRefreshOn(r) {
		d.Refresh = int(s.d.AutoRefresh / time.Second)
	}
	return d
}

// optionalSession returns the signed-in session for chrome on pages that do not
// require one (error pages, Help); ok is false when there is none.
func (s *server) optionalSession(r *http.Request) (session, bool) {
	token, ok := auth.SessionTokenFromRequest(r)
	if !ok {
		return session{}, false
	}
	id, err := s.d.Auth.Authenticate(r.Context(), token)
	if err != nil {
		return session{}, false
	}
	return session{id: id, token: token, view: s.viewFor(r.Context(), id.User.ID)}, true
}

// instanceName is the installation's label: Settings → General when wired (read live,
// file > database > default), else the configured value.
func (s *server) instanceName() string {
	if s.d.Settings != nil {
		return s.d.Settings.Current().General.InstanceName
	}
	return s.d.InstanceName
}

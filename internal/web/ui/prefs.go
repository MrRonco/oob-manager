package ui

import (
	"net/http"
	"strings"
	"time"
)

// formPrefs is the CSRF form name of the per-browser preference toggles.
const formPrefs = "prefs"

// refreshView is the auto-refresh toggle shown on live-data pages.
type refreshView struct {
	On    bool
	Every int
	CSRF  string
	Next  string
}

func (s *server) refreshFor(r *http.Request, sess session) refreshView {
	return refreshView{On: autoRefreshOn(r), Every: int(s.d.AutoRefresh / time.Second),
		CSRF: s.csrf.issue(formPrefs, sessionBinding(sess.token)), Next: r.URL.RequestURI()}
}

// prefsRefresh turns auto-refresh on or off for this browser (opt-in, WCAG 2.2.1) and
// goes back to the page the toggle was on. It needs a session and its CSRF token.
func (s *server) prefsRefresh(w http.ResponseWriter, r *http.Request, sess session) {
	form, ok := parseForm(w, r)
	if !ok || !s.csrf.verify(form.Get(csrfField), formPrefs, sessionBinding(sess.token)) {
		s.errorPage(w, r, http.StatusForbidden, msgFormExpired)
		return
	}
	if !s.allowPrefs(w, r, sess) {
		return
	}
	c := &http.Cookie{Name: refreshCookie, Value: "on", Path: "/", MaxAge: int((365 * 24 * time.Hour).Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
	if form.Get("refresh") != "on" {
		c.Value, c.MaxAge = "", -1
	}
	http.SetCookie(w, c)
	redirectLocal(w, r, form.Get("next"))
}

// redirectLocal is the only redirect to a computed target: p must pass localPath
// (same-origin absolute path), otherwise the overview is used. 303 See Other.
func redirectLocal(w http.ResponseWriter, r *http.Request, p string) {
	target := localPath(p, "/")
	http.Redirect(w, r, target, http.StatusSeeOther) //nolint:gosec // G710: target passed localPath (same-origin path only)
}

// localPath returns p when it is a same-origin absolute path (no scheme, host, "//",
// backslash or control characters), else def. It guards every redirect target taken
// from a form or query.
func localPath(p, def string) string {
	if p == "" || p[0] != '/' || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n\t") || len(p) > 512 {
		return def
	}
	for _, c := range p {
		if c < 0x20 || c == 0x7f {
			return def
		}
	}
	return p
}

// withTheme applies the browser's theme cookie (data-theme on <html>) and labels the
// theme switch; the switch returns to the page it was used on.
func withTheme(r *http.Request, d layoutData) layoutData {
	if c, err := r.Cookie(themeCookie); err == nil {
		d.Theme = themeFrom(c.Value)
	}
	f := themeCycle(d.Theme)
	// The path only: a query may carry untrusted values (stepup?next=), and the POST
	// re-validates the target anyway.
	f.CSRF, f.Next = d.ThemeForm.CSRF, r.URL.Path
	d.ThemeForm = f
	return d
}

// prefsTheme stores the theme for this browser ("auto" clears it) and returns to the
// page the switch was on. It needs a session and its CSRF token.
func (s *server) prefsTheme(w http.ResponseWriter, r *http.Request, sess session) {
	form, ok := parseForm(w, r)
	if !ok || !s.csrf.verify(form.Get(csrfField), formPrefs, sessionBinding(sess.token)) {
		s.errorPage(w, r, http.StatusForbidden, msgFormExpired)
		return
	}
	if !s.allowPrefs(w, r, sess) {
		return
	}
	theme := form.Get("theme")
	if theme != "auto" && themeFrom(theme) == "" {
		s.errorPage(w, r, http.StatusBadRequest, "Unknown theme.")
		return
	}
	c := &http.Cookie{Name: themeCookie, Value: theme, Path: "/", MaxAge: int((365 * 24 * time.Hour).Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
	if theme == "auto" {
		c.Value, c.MaxAge = "", -1
	}
	http.SetCookie(w, c)
	redirectLocal(w, r, form.Get("next"))
}

// allowPrefs applies the annotate rate (maintChangeRate, 30/min) to the cookie-only
// toggles in their own per-user bucket (plan 06 §3.1): no storage behind them, but every
// POST route has a limit (security.md §3). Not audited: nothing is changed server-side.
func (s *server) allowPrefs(w http.ResponseWriter, r *http.Request, sess session) bool {
	if ok, wait := s.maintLimit.allow("prefs:" + sess.id.User.ID); !ok {
		setRetryAfter(w, wait)
		s.errorPage(w, r, http.StatusTooManyRequests, "Too many changes in a short time. "+tryAgainIn(wait))
		return false
	}
	return true
}

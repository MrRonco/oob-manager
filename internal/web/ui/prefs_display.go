package ui

import (
	"errors"
	"net/http"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/display"
	"oob-manager/internal/settings"
)

// formDisplay is the CSRF form name of the Display preferences form.
const formDisplay = "display"

// displayView is the per-user Display preferences page: time zone, color theme,
// date and clock formats, temperature unit and table density.
type displayView struct {
	CSRF      string
	Zone      string // stored value; "" = use the app default
	AppZone   string
	Zones     []display.ZoneGroup
	Themes    []themeOption
	AppTheme  string
	Choices   []choiceGroup
	Sample    string // the current time in the effective format
	SampleISO string
	FormError string
	Saved     bool
}

type themeOption struct {
	ID, Label, About string
	Checked          bool
}

// choiceGroup is one radio group; Value "" is "Default (…)".
type choiceGroup struct {
	Name, Legend string
	Options      []choiceOption
}

type choiceOption struct {
	Value, Label, ID string
	Checked          bool
}

func (s *server) displayRoutes(mux *http.ServeMux) {
	mux.Handle("GET /preferences", s.page(authz.UserPrefs, s.displayPage))
	mux.Handle("POST /preferences", s.withSession(s.displaySubmit))
}

func (s *server) displayPage(w http.ResponseWriter, r *http.Request, sess session) {
	if s.d.Settings == nil {
		s.errorPage(w, r, http.StatusNotFound, "Display preferences are not available in this installation.")
		return
	}
	p, err := s.d.Settings.Prefs(r.Context(), sess.id.User.ID)
	if err != nil {
		s.d.Logger.Error("ui display preferences read failed", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "Your preferences could not be read.")
		return
	}
	v := s.displayViewOf(sess, p)
	v.Saved = r.URL.Query().Get("done") == "saved"
	s.renderDisplay(w, r, sess, http.StatusOK, v)
}

func (s *server) renderDisplay(w http.ResponseWriter, r *http.Request, sess session, status int, v displayView) {
	d := s.layoutFor(sess, "Display preferences", "", v)
	d.Crumbs = []crumb{{"Overview", "/"}, {Label: "Display preferences"}}
	if v.Saved {
		d.Flash, d.FlashKind = "Preferences saved.", "info"
	}
	s.render(w, r, status, pageDisplay, d)
}

func (s *server) displayViewOf(sess session, p display.Prefs) displayView {
	g := s.d.Settings.Current().General
	now := s.d.Now()
	v := displayView{CSRF: s.csrf.issue(formDisplay, sessionBinding(sess.token)), Zone: p.TimeZone,
		AppZone: g.TimeZone, Zones: display.ZoneGroups(), Sample: sess.tf().full(now), SampleISO: now.UTC().Format(rfc3339)}
	appTheme := themeLabel(display.Theme(g.Theme))
	v.AppTheme = appTheme
	v.Themes = append(v.Themes, themeOption{ID: "", Label: "App default (" + appTheme + ")", Checked: p.Theme == ""})
	for _, t := range display.Themes() {
		v.Themes = append(v.Themes, themeOption{ID: string(t.ID), Label: t.Label, About: t.About, Checked: p.Theme == string(t.ID)})
	}
	v.Choices = []choiceGroup{
		choiceGroupOf("date_format", "Date format", display.DateFormats(), p.DateFormat, g.DateFormat),
		choiceGroupOf("clock", "Clock", display.ClockFormats(), p.Clock, g.ClockFormat),
		choiceGroupOf("temp_unit", "Temperature", display.TempUnits(), p.TempUnit, g.TempUnit),
		choiceGroupOf("density", "Table density", display.Densities(), p.Density, g.Density),
	}
	return v
}

// choiceGroupOf lists "App default (…)" first, naming the current app default
// (Settings → General), then every choice. Nothing stored selects the app default.
func choiceGroupOf(name, legend string, cs []display.Choice, stored, appDefault string) choiceGroup {
	g := choiceGroup{Name: name, Legend: legend}
	g.Options = append(g.Options, choiceOption{Value: "", ID: "p-" + name + "-default", Checked: stored == "",
		Label: "App default (" + display.ChoiceLabel(appDefault, cs) + ")"})
	for _, c := range cs {
		g.Options = append(g.Options, choiceOption{Value: c.Value, Label: c.Label, ID: "p-" + name + "-" + c.Value,
			Checked: stored == c.Value})
	}
	return g
}

func themeLabel(t display.Theme) string {
	for _, x := range display.Themes() {
		if x.ID == t {
			return x.Label
		}
	}
	return string(t)
}

// displaySubmit saves the signed-in user's own preferences. Low risk: no step-up, but
// session, CSRF, authz (user.prefs), the per-user change limit and an audit row (by the
// settings service) all apply. "App default" is stored as empty, so a later change of
// the app default (Settings → General) reaches this user too; an explicit choice wins.
func (s *server) displaySubmit(w http.ResponseWriter, r *http.Request, sess session) {
	if s.d.Settings == nil {
		s.errorPage(w, r, http.StatusNotFound, "Display preferences are not available in this installation.")
		return
	}
	form, ok := parseForm(w, r)
	if !ok || !s.csrf.verify(form.Get(csrfField), formDisplay, sessionBinding(sess.token)) {
		s.deny(r, sess, authz.UserPrefs, "csrf")
		s.errorPage(w, r, http.StatusForbidden, msgFormExpired)
		return
	}
	if err := s.d.Authorize(sess.id.Principal(), authz.UserPrefs, true); err != nil {
		s.deny(r, sess, authz.UserPrefs, "forbidden")
		s.errorPage(w, r, http.StatusForbidden, "You do not have permission to change preferences.")
		return
	}
	if !s.allowChange(w, r, sess, authz.UserPrefs) {
		return
	}
	p := display.Prefs{TimeZone: form.Get("time_zone"), Theme: form.Get("theme"), DateFormat: form.Get("date_format"),
		Clock: form.Get("clock"), TempUnit: form.Get("temp_unit"), Density: form.Get("density")}
	if _, err := s.d.Settings.SetPrefs(r.Context(), actor(r, sess), p); err != nil {
		s.displayFailed(w, r, sess, p, err)
		return
	}
	http.Redirect(w, r, "/preferences?done=saved", http.StatusSeeOther)
}

func (s *server) displayFailed(w http.ResponseWriter, r *http.Request, sess session, p display.Prefs, err error) {
	if !errors.Is(err, settings.ErrInvalid) {
		s.d.Logger.Error("ui display preferences save failed", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "Your preferences could not be saved. Nothing was changed.")
		return
	}
	_ = s.record(r, audit.Entry{Principal: sess.id.User.Username, Role: string(sess.id.User.Role),
		Action: settings.ActionPrefsUpdate, Result: audit.ResultDenied, ErrorClass: "invalid"})
	v := s.displayViewOf(sess, display.Prefs{})
	v.FormError = "Not saved: choose a time zone, theme and formats from the lists."
	if _, zerr := display.LoadZone(p.TimeZone); p.TimeZone != "" && zerr != nil {
		v.FormError = "Not saved: unknown time zone. Choose one from the list."
	}
	s.renderDisplay(w, r, sess, http.StatusUnprocessableEntity, v)
}

const rfc3339 = "2006-01-02T15:04:05Z07:00"

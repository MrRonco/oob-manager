package ui

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/config"
	"oob-manager/internal/display"
	"oob-manager/internal/settings"
)

// generalView is Settings → General (slice S2).
type generalView struct {
	StepUp    stepUpNote
	CSRF      string
	Rev       int64
	Locked    bool // settings.locked lists general: every field is read-only
	Fields    []generalField
	Zones     []display.ZoneGroup
	Themes    []display.ThemeInfo
	Restart   []string // labels of saved values that apply after a restart
	FormError string
	CanSave   bool // at least one field is editable
	// History is the sensor history group (tech_doc §39) and HistorySize its size line.
	History     []generalField
	HistorySize string
	// Catalog is the firmware update check group and CatalogPanel its file-only keys,
	// status, upload and confirmation (plan 08 §10).
	Catalog      []generalField
	CatalogPanel *catalogPanel
}

// generalField is one setting on the form.
type generalField struct {
	Key, ID, Label, Help string
	Kind                 string // number, text, zone, theme or choice
	Value                string
	Unit                 string // "seconds", "minutes", …; "" for counts and names
	Min, Max             int
	FileManaged          bool   // "Managed by config.yaml": disabled with a lock badge
	Source               string // where the value comes from, as a sentence
	Restart              bool
	Invalid              bool
	// Resettable: a value saved from the browser that "Reset to default" can delete.
	Resettable bool
	Default    string // "30 minutes", "UTC"
	// Options are the closed set of a "choice" field (clock, date, temperature, density,
	// the history switches).
	Options []display.Choice
	// Zones and Themes are the lists of the zone and theme fields.
	Zones  []display.ZoneGroup
	Themes []display.ThemeInfo
}

func backToGeneral(*http.Request) string { return "/settings/general" }

// generalBackend is Settings when wired; the General routes answer 404 otherwise.
func (s *server) generalBackend(w http.ResponseWriter, r *http.Request) bool {
	if s.d.Settings == nil {
		s.errorPage(w, r, http.StatusNotFound, "General settings are not available in this installation.")
		return false
	}
	return true
}

func (s *server) generalPage(w http.ResponseWriter, r *http.Request, sess session) {
	if s.generalBackend(w, r) {
		s.renderGeneral(w, r, sess, http.StatusOK, nil, "", "")
	}
}

// renderGeneral shows the current settings; submitted (when not nil) re-fills the form
// after a refused save, and invalidKey marks the field the error is about.
func (s *server) renderGeneral(w http.ResponseWriter, r *http.Request, sess session, status int,
	submitted map[string]string, formErr, invalidKey string) {
	cur := s.d.Settings.Current()
	v := generalView{StepUp: s.stepUpNoteFor(r, sess), CSRF: s.csrf.issue(formSettings, sessionBinding(sess.token)),
		Rev: cur.Rev, Locked: cur.Locked, Zones: display.ZoneGroups(), Themes: display.Themes(), FormError: formErr,
		HistorySize: s.historySize(sess), CatalogPanel: s.catalogPanel(r.Context(), sess)}
	v.StepUp.Next = "/settings/general"
	pending := s.d.Settings.PendingRestart()
	for _, f := range cur.Fields() {
		gf := fieldOf(f, sess.tf())
		if val, ok := submitted[f.Key]; ok && !gf.FileManaged {
			gf.Value = val
		}
		gf.Invalid = f.Key == invalidKey
		gf.FileManaged = gf.FileManaged || cur.Locked
		gf.Resettable = f.Source == settings.SourceDB && !gf.FileManaged
		if slices.Contains(pending, f.Key) {
			v.Restart = append(v.Restart, f.Label)
		}
		v.CanSave = v.CanSave || !gf.FileManaged
		switch {
		case slices.Contains(settings.HistoryKeys(), f.Key):
			v.History = append(v.History, gf)
		case slices.Contains(settings.CatalogKeys(), f.Key):
			v.Catalog = append(v.Catalog, gf)
		case gf.Kind == "zone":
			gf.Zones = v.Zones
			v.Fields = append(v.Fields, gf)
		case gf.Kind == "theme":
			gf.Themes = v.Themes
			v.Fields = append(v.Fields, gf)
		default:
			v.Fields = append(v.Fields, gf)
		}
	}
	s.render(w, r, status, pageSettingsGeneral, s.settingsLayout(r, sess, "General", v))
}

func fieldOf(f settings.Field, tf timeFmt) generalField {
	gf := generalField{Key: f.Key, ID: "g-" + strings.NewReplacer(".", "-", "_", "-").Replace(f.Key), Label: f.Label,
		Help: f.Help, Value: f.Value, Restart: f.Restart, FileManaged: f.FileManaged(), Kind: "number"}
	switch f.Key {
	case config.KeyInstanceName:
		gf.Kind = "text"
	case config.KeyTimeZone:
		gf.Kind = "zone"
	case config.KeyTheme:
		gf.Kind = "theme"
	case config.KeyClockFormat, config.KeyDateFormat, config.KeyTempUnit, config.KeyDensity,
		config.KeyHistorySamplePSUs, config.KeyHistorySampleVoltages, config.KeyCatalogEnabled, config.KeyCatalogNotify:
		gf.Kind, gf.Options = "choice", choicesFor(f.Key)
	}
	if f.Unit != settings.UnitCount && f.Unit != settings.UnitName && f.Unit != settings.UnitBool && f.Unit != settings.UnitText {
		gf.Unit = string(f.Unit)
	}
	gf.Min, gf.Max = bounds(f.Key)
	gf.Default = f.Default
	if gf.Kind == "choice" {
		gf.Default = display.ChoiceLabel(f.Default, gf.Options)
	}
	if gf.Unit != "" {
		gf.Default += " " + gf.Unit
	}
	if gf.Default == "" {
		gf.Default = "none"
	}
	switch f.Source {
	case settings.SourceFile:
		gf.Source = "Set in config.yaml (" + f.Key + "). Edit the file and restart to change it."
	case settings.SourceDB:
		gf.Source = "Saved by " + f.UpdatedBy + " on " + tf.full(f.UpdatedAt) + "."
	default:
		gf.Source = "Default."
	}
	return gf
}

// choicesFor is the closed set of a display default key.
func choicesFor(key string) []display.Choice {
	switch key {
	case config.KeyClockFormat:
		return display.ClockFormats()
	case config.KeyDateFormat:
		return display.DateFormats()
	case config.KeyHistorySamplePSUs, config.KeyHistorySampleVoltages, config.KeyCatalogEnabled:
		return []display.Choice{{Value: "on", Label: "On"}, {Value: "off", Label: "Off"}}
	case config.KeyCatalogNotify:
		return []display.Choice{{Value: "urgent", Label: "Urgent updates only"}, {Value: "all", Label: "All updates"},
			{Value: "off", Label: "None"}}
	case config.KeyTempUnit:
		return display.TempUnits()
	default:
		return display.Densities()
	}
}

// bounds are the form's min and max in the field's unit (the server validates anyway).
func bounds(key string) (lo, hi int) {
	mins := func(d time.Duration) int { return int(d / time.Minute) }
	switch key {
	case config.KeyPollInterval:
		return int(config.PollFloor / time.Second), int(config.MaxPollInterval / time.Second)
	case config.KeyStaleMultiplier:
		return config.MinStaleMultiplier, config.MaxStaleMultiplier
	case config.KeySessionIdle:
		return mins(config.MinSessionIdle), mins(config.MaxSessionIdle)
	case config.KeySessionMax:
		return int(config.MinSessionMax / time.Hour), int(config.MaxSessionMax / time.Hour)
	case config.KeyStepUpWindow:
		return 1, mins(config.MaxStepUpWindow)
	case config.KeyLoginIPPerMin:
		return config.MinLoginIPPerMin, config.MaxLoginIPPerMin
	case config.KeyLoginAcctPerHour:
		return config.MinLoginAcctPerHour, config.MaxLoginAcctPerHour
	case config.KeyHistoryRawDays:
		return config.MinHistoryRawDays, config.MaxHistoryRawDays
	case config.KeyHistoryHourlyDays:
		return config.MinHistoryHourlyDays, config.MaxHistoryHourlyDays
	case config.KeyHistoryDailyDays:
		return config.MinHistoryDailyDays, config.MaxHistoryDailyDays
	case config.KeyCatalogCheckEvery:
		return config.MinCatalogCheckDays, config.MaxCatalogCheckDays
	default:
		return 0, 0
	}
}

// saveGeneral applies the form (only the fields the browser sent: disabled, file-managed
// inputs are not submitted). The settings service validates with the config.yaml
// validator, refuses file-managed keys and stale revisions, and audits old → new.
func (s *server) saveGeneral(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	if !s.generalBackend(w, r) {
		return
	}
	submitted := map[string]string{}
	for _, k := range config.GeneralKeys() {
		if vals, ok := form[k]; ok && len(vals) == 1 {
			submitted[k] = vals[0]
		}
	}
	rev, err := strconv.ParseInt(form.Get("rev"), 10, 64)
	if err != nil {
		s.renderGeneral(w, r, sess, http.StatusBadRequest, submitted, "The form could not be read. Reload the page.", "")
		return
	}
	changes, err := s.d.Settings.UpdateGeneral(r.Context(), actor(r, sess), rev, submitted)
	switch {
	case err == nil && len(changes) == 0:
		http.Redirect(w, r, "/settings/general?done=general-unchanged", http.StatusSeeOther)
	case err == nil:
		for _, c := range changes {
			s.catalogEnabledChange(r.Context(), actor(r, sess), c.Field, c.Before, c.After)
		}
		http.Redirect(w, r, "/settings/general?done=general", http.StatusSeeOther)
	case errors.Is(err, settings.ErrConflict):
		s.renderGeneral(w, r, sess, http.StatusConflict, nil, err.Error(), "")
	case errors.Is(err, settings.ErrLocked):
		s.errorPage(w, r, http.StatusForbidden, "This setting is managed by config.yaml or the General section is locked. Nothing was changed.")
	case errors.Is(err, settings.ErrInvalid):
		s.renderGeneral(w, r, sess, http.StatusUnprocessableEntity, submitted, generalErrorText(err), invalidKeyOf(err))
	default:
		s.d.Logger.Error("ui general settings save failed", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "The settings could not be saved. Nothing was changed.")
	}
}

// generalErrorText is the validator's message without the error prefix; it only ever
// names config keys and bounds, never echoes free text beyond the submitted value.
func generalErrorText(err error) string {
	msg := strings.TrimPrefix(err.Error(), settings.ErrInvalid.Error()+": ")
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	return "Not saved: " + msg
}

// invalidKeyOf finds the first General key the validation message names.
func invalidKeyOf(err error) string {
	msg := err.Error()
	first, at := "", len(msg)
	for _, k := range config.GeneralKeys() {
		if i := strings.Index(msg, k); i >= 0 && i < at {
			first, at = k, i
		}
	}
	return first
}

// resetGeneral deletes one saved value (the "Reset to default" button, which submits
// the General form to this route with reset=<key>). Only reset and rev are read.
func (s *server) resetGeneral(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	if !s.generalBackend(w, r) {
		return
	}
	rev, err := strconv.ParseInt(form.Get("rev"), 10, 64)
	if err != nil {
		s.renderGeneral(w, r, sess, http.StatusBadRequest, nil, "The form could not be read. Reload the page.", "")
		return
	}
	key := form.Get("reset")
	changes, err := s.d.Settings.ResetGeneral(r.Context(), actor(r, sess), rev, key)
	switch {
	case err == nil && len(changes) == 0:
		http.Redirect(w, r, "/settings/general?done=general-unchanged", http.StatusSeeOther)
	case err == nil:
		http.Redirect(w, r, "/settings/general?done=general-reset", http.StatusSeeOther)
	case errors.Is(err, settings.ErrConflict):
		s.renderGeneral(w, r, sess, http.StatusConflict, nil, err.Error(), "")
	case errors.Is(err, settings.ErrLocked):
		s.errorPage(w, r, http.StatusForbidden, "This setting is managed by config.yaml or the General section is locked. Nothing was changed.")
	case errors.Is(err, settings.ErrInvalid):
		s.renderGeneral(w, r, sess, http.StatusBadRequest, nil, generalErrorText(err), invalidKeyOf(err))
	default:
		s.d.Logger.Error("ui general settings reset failed", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "The setting could not be reset. Nothing was changed.")
	}
}

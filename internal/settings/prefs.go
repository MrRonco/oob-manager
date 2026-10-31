package settings

import (
	"context"
	"fmt"

	"oob-manager/internal/admin"
	"oob-manager/internal/config"
	"oob-manager/internal/display"
	"oob-manager/internal/store"
)

// prefKeys names the preference fields in audit rows, in display order.
func prefKeys() []string {
	return []string{"time_zone", "theme", "date_format", "clock", "temp_unit", "density"}
}

func prefValues(p display.Prefs) map[string]string {
	or := func(v string) string {
		if v == "" {
			return "default"
		}
		return v
	}
	return map[string]string{"time_zone": or(p.TimeZone), "theme": or(p.Theme), "date_format": or(p.DateFormat),
		"clock": or(p.Clock), "temp_unit": or(p.TempUnit), "density": or(p.Density)}
}

// Prefs returns a user's stored display preferences ("" fields = default).
func (s *Service) Prefs(ctx context.Context, userID string) (display.Prefs, error) {
	p, err := s.cfg.DB.Prefs().Get(ctx, userID)
	if err != nil {
		return display.Prefs{}, err
	}
	return display.Prefs{TimeZone: p.TimeZone, Theme: p.Theme, DateFormat: p.DateFormat, Clock: p.Clock,
		TempUnit: p.TempUnit, Density: p.Density}, nil
}

// View resolves a user's preferences over the current app defaults. An empty userID
// (a signed-out page) gets the app defaults.
func (s *Service) View(ctx context.Context, userID string) (display.View, error) {
	app := AppDisplay(s.Current().General)
	if userID == "" {
		return display.Resolve(display.Prefs{}, app), nil
	}
	p, err := s.Prefs(ctx, userID)
	if err != nil {
		return display.Resolve(display.Prefs{}, app), err
	}
	return display.Resolve(p, app), nil
}

// AppDisplay is the app-wide display defaults of g (Settings → General, config ui.*).
func AppDisplay(g config.General) display.Prefs {
	return display.Prefs{TimeZone: g.TimeZone, Theme: g.Theme, DateFormat: g.DateFormat, Clock: g.ClockFormat,
		TempUnit: g.TempUnit, Density: g.Density}
}

// SetPrefs replaces a's own preferences after validating them. Low risk, so no
// step-up, but the change is audited (old → new) in the same transaction. Nothing is
// written when nothing changed.
func (s *Service) SetPrefs(ctx context.Context, a admin.Actor, p display.Prefs) ([]Change, error) {
	if a.UserID == "" {
		return nil, fmt.Errorf("%w: no user", ErrInvalid)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	old, err := s.Prefs(ctx, a.UserID)
	if err != nil {
		return nil, err
	}
	changes := Diff(prefKeys(), prefValues(old), prefValues(p), func(string) bool { return true })
	if len(changes) == 0 {
		return nil, nil
	}
	err = s.cfg.DB.WithTx(ctx, func(tx *store.Tx) error {
		row := store.UserPrefs{UserID: a.UserID, TimeZone: p.TimeZone, Theme: p.Theme, DateFormat: p.DateFormat,
			Clock: p.Clock, TempUnit: p.TempUnit, Density: p.Density, UpdatedAt: s.cfg.Now()}
		if perr := tx.Prefs().Put(ctx, row); perr != nil {
			return perr
		}
		_, rerr := s.cfg.Audit.RecordTx(ctx, tx, entry(a, ActionPrefsUpdate, params("self", changes, nil)))
		return rerr
	})
	if err != nil {
		return nil, err
	}
	return changes, nil
}

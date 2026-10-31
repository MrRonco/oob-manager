package ui

import (
	"context"
	"time"

	"oob-manager/internal/display"
)

// viewFor resolves how a page is shown to userID ("" = signed out): time zone, color
// theme, date and clock formats, temperature unit and table density. Without a
// Settings backend every page uses Deps.Location and the built-in defaults. A lookup
// failure is logged and falls back to the app defaults: it never fails a page.
func (s *server) viewFor(ctx context.Context, userID string) display.View {
	if s.d.Settings == nil {
		v := display.Defaults()
		v.Loc, v.Zone = s.d.Location, s.d.Location.String()
		return v
	}
	v, err := s.d.Settings.View(ctx, userID)
	if err != nil {
		s.d.Logger.Error("ui display preferences lookup failed", "err", err)
	}
	return v
}

// tf is the time format of the signed-in user.
func (sess session) tf() timeFmt { return fmtFor(sess.view) }

// unit is the temperature unit of the signed-in user.
func (sess session) unit() tempUnit { return unitOf(sess.view.Temp) }

// stepUpWindow is the step-up window in force (live from Settings when wired).
func (s *server) stepUpWindow() time.Duration {
	if s.d.Settings != nil {
		return s.d.Settings.Current().General.StepUpWindow
	}
	return s.d.StepUpWindow
}

// loginIPRate and loginAcctRate are the sign-in limits in force. With Settings they
// are read on every attempt, so a change applies at once; the limiters keep their
// buckets, so a change never hands out a fresh allowance.
func (s *server) loginIPRate() RateLimit {
	if s.d.Settings != nil {
		return RateLimit{Events: s.d.Settings.Current().General.LoginIPPerMin, Per: time.Minute}
	}
	return s.d.LoginPerIP
}

func (s *server) loginAcctRate() RateLimit {
	if s.d.Settings != nil {
		return RateLimit{Events: s.d.Settings.Current().General.LoginAcctPerHour, Per: time.Hour}
	}
	return s.d.LoginPerAccount
}

// Package display holds the closed sets behind the display preferences: color themes,
// time zones, date and clock formats, temperature unit and table density. Both the
// app-wide defaults (Settings → General, config `ui.*`) and each user's own
// preferences are validated here, so the file, the database and the forms accept
// exactly the same values.
//
// Storage and polling stay UTC; everything here only changes how a value is shown.
package display

import (
	"errors"
	"fmt"
	"time"

	_ "time/tzdata" // the image is distroless: no /usr/share/zoneinfo
)

// UTC is the default time zone and the first choice in every zone list.
const UTC = "UTC"

// ErrInvalid is wrapped by every validation error of this package.
var ErrInvalid = errors.New("display: invalid value")

// Theme is a color palette (a token set over the direction B CSS variables). The
// light/dark mode is separate: every theme has both variants.
type Theme string

// Themes. The value is the CSS attribute value (<html data-palette="…">).
const (
	ThemeGraphite     Theme = "graphite"
	ThemeHighContrast Theme = "high-contrast"
	ThemeSolarized    Theme = "solarized"
	ThemeNord         Theme = "nord"
	ThemeDracula      Theme = "dracula"
	ThemeColorBlind   Theme = "colorblind"
)

// DefaultTheme is the built-in palette.
const DefaultTheme = ThemeGraphite

// ThemeInfo describes a theme for the pickers.
type ThemeInfo struct {
	ID    Theme
	Label string
	About string
}

// Themes returns every theme in display order (a fresh slice each call).
func Themes() []ThemeInfo {
	return []ThemeInfo{
		{ThemeGraphite, "Graphite", "The default: cool grays with a cyan accent."},
		{ThemeHighContrast, "High contrast", "Pure black and white, 7:1 text and a thicker focus ring."},
		{ThemeSolarized, "Solarized", "Ethan Schoonover's warm, low-glare palette."},
		{ThemeNord, "Nord", "Arctic blues and frost."},
		{ThemeDracula, "Dracula", "Purple and pink on deep gray (Alucard in light mode)."},
		{ThemeColorBlind, "Color-blind safe", "Okabe-Ito status colors (blue, orange, vermillion), safe for red-green color blindness."},
	}
}

// ParseTheme validates a theme name exactly.
func ParseTheme(s string) (Theme, error) {
	for _, t := range Themes() {
		if string(t.ID) == s {
			return t.ID, nil
		}
	}
	return "", fmt.Errorf("%w: unknown theme %q", ErrInvalid, s)
}

// DateFormat is how dates are written.
type DateFormat string

// Date formats.
const (
	DateISO DateFormat = "iso" // 2026-10-21
	DateUS  DateFormat = "us"  // 10/21/2026
)

// ClockFormat is a 24-hour or 12-hour clock.
type ClockFormat string

// Clock formats.
const (
	Clock24 ClockFormat = "24h"
	Clock12 ClockFormat = "12h"
)

// TempUnit is the temperature unit.
type TempUnit string

// Temperature units.
const (
	Celsius    TempUnit = "c"
	Fahrenheit TempUnit = "f"
)

// Density is the table row density.
type Density string

// Densities.
const (
	Compact     Density = "compact"
	Comfortable Density = "comfortable"
)

// Choice is one option of a closed set, for the forms.
type Choice struct{ Value, Label string }

// DateFormats lists the date format choices (fresh slices, like the other lists).
func DateFormats() []Choice {
	return []Choice{{string(DateISO), "ISO (2026-10-21)"}, {string(DateUS), "US (10/21/2026)"}}
}

// ClockFormats lists the clock choices.
func ClockFormats() []Choice {
	return []Choice{{string(Clock24), "24-hour (14:05)"}, {string(Clock12), "12-hour (2:05 PM)"}}
}

// TempUnits lists the temperature unit choices.
func TempUnits() []Choice {
	return []Choice{{string(Celsius), "Celsius (°C)"}, {string(Fahrenheit), "Fahrenheit (°F)"}}
}

// Densities lists the table density choices.
func Densities() []Choice {
	return []Choice{{string(Compact), "Compact"}, {string(Comfortable), "Comfortable"}}
}

// InChoices reports whether v is one of cs's values.
func InChoices(v string, cs []Choice) bool {
	for _, c := range cs {
		if c.Value == v {
			return true
		}
	}
	return false
}

func inChoices(v string, cs []Choice) bool { return InChoices(v, cs) }

// ChoiceValues lists cs's values for messages ("24h, 12h").
func ChoiceValues(cs []Choice) string {
	out := ""
	for i, c := range cs {
		if i > 0 {
			out += ", "
		}
		out += c.Value
	}
	return out
}

// ChoiceLabel is the label of value v in cs (v itself when unknown).
func ChoiceLabel(v string, cs []Choice) string {
	for _, c := range cs {
		if c.Value == v {
			return c.Label
		}
	}
	return v
}

// Prefs is one user's stored preferences. An empty field means "use the default"
// (the app default for the zone and theme, the built-in default otherwise).
type Prefs struct {
	TimeZone   string
	Theme      string
	DateFormat string
	Clock      string
	TempUnit   string
	Density    string
}

// Validate checks every non-empty field against its closed set.
func (p Prefs) Validate() error {
	var errs []error
	if p.TimeZone != "" {
		if _, err := LoadZone(p.TimeZone); err != nil {
			errs = append(errs, err)
		}
	}
	if p.Theme != "" {
		if _, err := ParseTheme(p.Theme); err != nil {
			errs = append(errs, err)
		}
	}
	for _, f := range []struct {
		name, v string
		set     []Choice
	}{
		{"date format", p.DateFormat, DateFormats()}, {"clock", p.Clock, ClockFormats()},
		{"temperature unit", p.TempUnit, TempUnits()}, {"density", p.Density, Densities()},
	} {
		if f.v != "" && !inChoices(f.v, f.set) {
			errs = append(errs, fmt.Errorf("%w: unknown %s %q", ErrInvalid, f.name, f.v))
		}
	}
	return errors.Join(errs...)
}

// View is the resolved presentation of one request: the effective zone, theme and
// formats. It is a value; Loc is never nil after Resolve.
type View struct {
	Zone    string
	Loc     *time.Location
	Theme   Theme
	Date    DateFormat
	Clock   ClockFormat
	Temp    TempUnit
	Density Density
}

// Defaults is the built-in view (UTC, Graphite, ISO, 24 h, °C, compact).
func Defaults() View {
	return View{Zone: UTC, Loc: time.UTC, Theme: DefaultTheme, Date: DateISO, Clock: Clock24,
		Temp: Celsius, Density: Compact}
}

// Resolve applies the user's preferences over the app defaults (Settings → General,
// config ui.*), which apply over the built-in Defaults. Invalid values (for example a
// zone removed from a later tz database) fall back instead of failing the page.
func Resolve(user, app Prefs) View {
	return apply(apply(Defaults(), app), user)
}

// apply overlays every valid, non-empty field of p on v.
func apply(v View, user Prefs) View {
	if loc, err := LoadZone(user.TimeZone); user.TimeZone != "" && err == nil {
		v.Zone, v.Loc = user.TimeZone, loc
	}
	if t, err := ParseTheme(user.Theme); err == nil {
		v.Theme = t
	}
	if inChoices(user.DateFormat, DateFormats()) {
		v.Date = DateFormat(user.DateFormat)
	}
	if inChoices(user.Clock, ClockFormats()) {
		v.Clock = ClockFormat(user.Clock)
	}
	if inChoices(user.TempUnit, TempUnits()) {
		v.Temp = TempUnit(user.TempUnit)
	}
	if inChoices(user.Density, Densities()) {
		v.Density = Density(user.Density)
	}
	return v
}

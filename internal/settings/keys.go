// Package settings resolves the runtime-managed settings (docs/settings_design.md §2):
// precedence config.yaml > database > built-in default, "Managed by config.yaml" locks,
// settings.locked sections, the redacting Diff for audit rows and the live Provider.
// Service applies browser changes: validated with the same validator as the file
// (config.ValidateGeneral), compare-and-set on a revision, and written in one
// transaction with the audit row describing them. It also stores each user's own
// display preferences.
//
// Slice S2 covers the General section; slice S4 adds Integrations (the GELF audit
// target, tech_doc §34) next to it: a section is a list of key specs plus a validator.
// (S3's servers have their own rows, internal/registry.)
package settings

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/config"
)

// Unit is how a key is entered on the form and stored as JSON.
type Unit string

// Units of the General keys.
const (
	UnitSeconds Unit = "seconds"
	UnitMinutes Unit = "minutes"
	UnitHours   Unit = "hours"
	UnitCount   Unit = "count"
	UnitDays    Unit = "days" // a whole number of days (the history retention)
	UnitName    Unit = "name" // a closed-set name (time zone, theme)
)

// Spec describes one runtime-managed key.
type Spec struct {
	Key   string
	Label string
	Help  string
	Unit  Unit
	// Restart is true when a change applies only after a restart (the pollers read it
	// once at startup); everything else is read on every use.
	Restart bool
}

// GeneralSpecs returns the General section's keys in display order (fresh slice).
func GeneralSpecs() []Spec {
	return []Spec{
		{config.KeyInstanceName, "Instance name", "Shown in the header, on the sign-in page and in webhook notifications. Plain text, at most 64 bytes (fewer characters with accents); empty for none.", UnitText, false},
		{config.KeyPollInterval, "Poll interval", "How often every BMC is read (30 seconds to 10 minutes).", UnitSeconds, false},
		{config.KeyStaleMultiplier, "Stale after (poll intervals)", "Data older than this many poll intervals is shown as stale (2 to 10).", UnitCount, false},
		{config.KeySessionIdle, "Session idle timeout", "Sign out after this long without activity (5 to 120 minutes).", UnitMinutes, false},
		{config.KeySessionMax, "Session maximum", "Sign out this long after sign-in, whatever the activity (1 to 24 hours).", UnitHours, false},
		{config.KeyStepUpWindow, "Step-up window", "How long an authenticator code keeps dangerous actions unlocked (1 to 5 minutes).", UnitMinutes, false},
		{config.KeyLoginIPPerMin, "Sign-in attempts per address", "Per minute, from one IP address (1 to 10).", UnitCount, false},
		{config.KeyLoginAcctPerHour, "Sign-in attempts per account", "Per hour, for one username (3 to 20).", UnitCount, false},
		{config.KeyTimeZone, "Display time zone", "Default for everyone; each user can choose their own. Storage stays UTC.", UnitName, false},
		{config.KeyTheme, "Default color theme", "Used on the sign-in page and by users who have not picked one.", UnitName, false},
		{config.KeyClockFormat, "Default clock", "24-hour or 12-hour; users can choose their own.", UnitName, false},
		{config.KeyDateFormat, "Default date format", "ISO (2026-10-21) or US (10/21/2026); users can choose their own.", UnitName, false},
		{config.KeyTempUnit, "Default temperature unit", "°C or °F; users can choose their own.", UnitName, false},
		{config.KeyDensity, "Default table density", "Compact or comfortable rows; users can choose their own.", UnitName, false},
		{config.KeyHistoryRawDays, "Keep every reading for", "Raw samples, one per poll (1 to 30 days). Lowering it deletes older readings at the next hourly prune.", UnitDays, false},
		{config.KeyHistoryHourlyDays, "Keep hourly summaries for", "Minimum, average and maximum per hour (7 to 730 days, at least the raw period).", UnitDays, false},
		{config.KeyHistoryDailyDays, "Keep daily summaries for", "Minimum, average and maximum per day (30 to 1825 days, at least the hourly period).", UnitDays, false},
		{config.KeyHistorySamplePSUs, "Record power supply input and output", "Two series per power supply. Applies from the next poll.", UnitBool, false},
		{config.KeyHistorySampleVoltages, "Record voltage rails", "Analog rails only; power-good signals are never recorded. Applies from the next poll.", UnitBool, false},
		{config.KeyCatalogEnabled, "Check the vendor catalog online", "Downloads the vendor's signed firmware catalog on a schedule. Nothing about your servers is sent, and nothing is ever installed.", UnitBool, false},
		{config.KeyCatalogCheckEvery, "Check every", "Days between online checks (1 to 30).", UnitDays, false},
		{config.KeyCatalogNotify, "Notify about", "New updates sent to the notification targets: urgent only, all, or none.", UnitName, false},
	}
}

// CatalogKeys are the General keys of the firmware update check group (plan 08), in
// display order.
func CatalogKeys() []string { return config.CatalogKeys() }

// HistoryKeys are the General keys of the History group (tech_doc §39), in display order.
func HistoryKeys() []string {
	return []string{config.KeyHistoryRawDays, config.KeyHistoryHourlyDays, config.KeyHistoryDailyDays,
		config.KeyHistorySamplePSUs, config.KeyHistorySampleVoltages}
}

// specFor returns the General spec for key.
func specFor(key string) (Spec, bool) {
	for _, s := range GeneralSpecs() {
		if s.Key == key {
			return s, true
		}
	}
	return Spec{}, false
}

// value is one key's value: a duration, a count, a name or text, or a flag.
type value struct {
	d time.Duration
	n int
	s string
	b bool
}

func get(g config.General, key string) value {
	switch key {
	case config.KeyPollInterval:
		return value{d: g.PollInterval}
	case config.KeyStaleMultiplier:
		return value{n: g.StaleMultiplier}
	case config.KeySessionIdle:
		return value{d: g.SessionIdle}
	case config.KeySessionMax:
		return value{d: g.SessionMax}
	case config.KeyStepUpWindow:
		return value{d: g.StepUpWindow}
	case config.KeyLoginIPPerMin:
		return value{n: g.LoginIPPerMin}
	case config.KeyLoginAcctPerHour:
		return value{n: g.LoginAcctPerHour}
	case config.KeyInstanceName:
		return value{s: g.InstanceName}
	case config.KeyTimeZone:
		return value{s: g.TimeZone}
	case config.KeyClockFormat:
		return value{s: g.ClockFormat}
	case config.KeyDateFormat:
		return value{s: g.DateFormat}
	case config.KeyTempUnit:
		return value{s: g.TempUnit}
	case config.KeyDensity:
		return value{s: g.Density}
	case config.KeyHistoryRawDays, config.KeyHistoryHourlyDays, config.KeyHistoryDailyDays,
		config.KeyHistorySamplePSUs, config.KeyHistorySampleVoltages:
		return getHistory(g, key)
	case config.KeyCatalogEnabled:
		return value{b: g.CatalogEnabled}
	case config.KeyCatalogCheckEvery:
		return value{n: g.CatalogCheckDays}
	case config.KeyCatalogNotify:
		return value{s: g.CatalogNotify}
	default: // config.KeyTheme
		return value{s: g.Theme}
	}
}

// set returns a copy of g with key set to v.
func set(g config.General, key string, v value) config.General {
	switch key {
	case config.KeyPollInterval:
		g.PollInterval = v.d
	case config.KeyStaleMultiplier:
		g.StaleMultiplier = v.n
	case config.KeySessionIdle:
		g.SessionIdle = v.d
	case config.KeySessionMax:
		g.SessionMax = v.d
	case config.KeyStepUpWindow:
		g.StepUpWindow = v.d
	case config.KeyLoginIPPerMin:
		g.LoginIPPerMin = v.n
	case config.KeyLoginAcctPerHour:
		g.LoginAcctPerHour = v.n
	case config.KeyInstanceName:
		g.InstanceName = v.s
	case config.KeyTimeZone:
		g.TimeZone = v.s
	case config.KeyTheme:
		g.Theme = v.s
	case config.KeyClockFormat:
		g.ClockFormat = v.s
	case config.KeyDateFormat:
		g.DateFormat = v.s
	case config.KeyTempUnit:
		g.TempUnit = v.s
	case config.KeyDensity:
		g.Density = v.s
	case config.KeyCatalogEnabled:
		g.CatalogEnabled = v.b
	case config.KeyCatalogCheckEvery:
		g.CatalogCheckDays = v.n
	case config.KeyCatalogNotify:
		g.CatalogNotify = v.s
	default:
		g = setHistory(g, key, v)
	}
	return g
}

func getHistory(g config.General, key string) value {
	switch key {
	case config.KeyHistoryRawDays:
		return value{n: g.HistoryRawDays}
	case config.KeyHistoryHourlyDays:
		return value{n: g.HistoryHourlyDays}
	case config.KeyHistoryDailyDays:
		return value{n: g.HistoryDailyDays}
	case config.KeyHistorySamplePSUs:
		return value{b: g.SamplePSUs}
	default: // config.KeyHistorySampleVoltages
		return value{b: g.SampleVoltages}
	}
}

// setHistory returns a copy of g with the history key set to v.
func setHistory(g config.General, key string, v value) config.General {
	switch key {
	case config.KeyHistoryRawDays:
		g.HistoryRawDays = v.n
	case config.KeyHistoryHourlyDays:
		g.HistoryHourlyDays = v.n
	case config.KeyHistoryDailyDays:
		g.HistoryDailyDays = v.n
	case config.KeyHistorySamplePSUs:
		g.SamplePSUs = v.b
	case config.KeyHistorySampleVoltages:
		g.SampleVoltages = v.b
	}
	return g
}

func (u Unit) duration() time.Duration {
	switch u {
	case UnitSeconds:
		return time.Second
	case UnitMinutes:
		return time.Minute
	case UnitHours:
		return time.Hour
	default:
		return 0
	}
}

// Display renders a value as the form shows it: whole units ("5"), a Go duration when
// it is not a whole number of units ("90s"), or the name.
func (s Spec) display(v value) string {
	switch {
	case s.Unit == UnitName, s.Unit == UnitText:
		return v.s
	case s.Unit == UnitBool:
		return map[bool]string{true: "on", false: "off"}[v.b]
	case s.Unit == UnitCount, s.Unit == UnitDays:
		return strconv.Itoa(v.n)
	case v.d%s.Unit.duration() == 0:
		return strconv.FormatInt(int64(v.d/s.Unit.duration()), 10)
	default:
		return v.d.String()
	}
}

// parseForm reads a form value in the spec's unit. Durations are whole numbers of the
// unit; counts are integers; names are passed through (validated later).
func (s Spec) parseForm(raw string) (value, error) {
	raw = strings.TrimSpace(raw)
	switch s.Unit {
	case UnitName, UnitText:
		if s.Key == config.KeyGELFPin {
			raw = normalisePin(raw)
		}
		return value{s: raw}, nil
	case UnitBool:
		switch raw {
		case "on":
			return value{b: true}, nil
		case "off":
			return value{}, nil
		}
		return value{}, fmt.Errorf("%s must be on or off", s.Label)
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > 1_000_000 {
		return value{}, fmt.Errorf("%s must be a whole number", s.Label)
	}
	if s.Unit == UnitCount || s.Unit == UnitDays {
		return value{n: n}, nil
	}
	return value{d: time.Duration(n) * s.Unit.duration()}, nil
}

// encode is the stored JSON: a duration string, a number or a string.
func (s Spec) encode(v value) string {
	var b []byte
	switch s.Unit {
	case UnitName, UnitText:
		b, _ = json.Marshal(v.s)
	case UnitBool:
		b, _ = json.Marshal(v.b)
	case UnitCount, UnitDays:
		b, _ = json.Marshal(v.n)
	default:
		b, _ = json.Marshal(v.d.String())
	}
	return string(b)
}

// decode parses a stored JSON value.
func (s Spec) decode(raw string) (value, error) {
	switch s.Unit {
	case UnitName, UnitText:
		var v string
		err := json.Unmarshal([]byte(raw), &v)
		return value{s: v}, err
	case UnitBool:
		var b bool
		err := json.Unmarshal([]byte(raw), &b)
		return value{b: b}, err
	case UnitCount, UnitDays:
		var n int
		err := json.Unmarshal([]byte(raw), &n)
		return value{n: n}, err
	default:
		var str string
		if err := json.Unmarshal([]byte(raw), &str); err != nil {
			return value{}, err
		}
		d, err := time.ParseDuration(str)
		return value{d: d}, err
	}
}

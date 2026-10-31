package config

import (
	"bytes"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"oob-manager/internal/display"
)

// Runtime-managed settings keys (settings_design.md §2, §4). Each is also the dotted
// path of its config.yaml key, so a lock badge can name the file key.
const (
	KeyPollInterval     = "poll.interval"
	KeyStaleMultiplier  = "poll.stale_multiplier"
	KeySessionIdle      = "auth.session_idle"
	KeySessionMax       = "auth.session_max"
	KeyStepUpWindow     = "auth.stepup_window" //nolint:gosec // G101: a config key name, not a credential
	KeyLoginIPPerMin    = "ratelimit.login_ip_per_min"
	KeyLoginAcctPerHour = "ratelimit.login_acct_per_hour"
	KeyTimeZone         = "ui.time_zone"
	KeyTheme            = "ui.theme"
	KeyClockFormat      = "ui.clock_format"
	KeyDateFormat       = "ui.date_format"
	KeyTempUnit         = "ui.temperature_unit"
	KeyDensity          = "ui.density"
	KeyInstanceName     = "ui.instance_name"
)

// GeneralKeys returns the General section's keys in display order (fresh slice).
func GeneralKeys() []string {
	return []string{KeyInstanceName, KeyPollInterval, KeyStaleMultiplier, KeySessionIdle, KeySessionMax, KeyStepUpWindow,
		KeyLoginIPPerMin, KeyLoginAcctPerHour, KeyTimeZone, KeyTheme, KeyClockFormat, KeyDateFormat, KeyTempUnit,
		KeyDensity, KeyHistoryRawDays, KeyHistoryHourlyDays, KeyHistoryDailyDays, KeyHistorySamplePSUs,
		KeyHistorySampleVoltages, KeyCatalogEnabled, KeyCatalogCheckEvery, KeyCatalogNotify}
}

// Settings sections that settings.locked can make read-only.
const (
	SectionGeneral      = "general"
	SectionServers      = "servers"
	SectionIntegrations = "integrations"
)

// Bounds of the General settings: the safe range, enforced for the file and the
// database alike (settings_design.md §4).
const (
	MaxPollInterval         = 10 * time.Minute
	MinStaleMultiplier      = 2
	MaxStaleMultiplier      = 10
	MinSessionIdle          = 5 * time.Minute
	MaxSessionIdle          = 2 * time.Hour
	MinSessionMax           = time.Hour
	MaxSessionMax           = 24 * time.Hour
	MinStepUpWindow         = time.Minute // design range 1–5 min; tests use the cmd env hook, never config
	MaxStepUpWindow         = 5 * time.Minute
	MinLoginIPPerMin        = 1
	MaxLoginIPPerMin        = 10
	MinLoginAcctPerHour     = 3
	MaxLoginAcctPerHour     = 20
	DefaultStaleMultiplier  = 3
	DefaultLoginIPPerMin    = 5
	DefaultLoginAcctPerHour = 10
)

// General is the General section of Settings: one value per GeneralKeys entry.
type General struct {
	// InstanceName labels the installation in the header, on the sign-in page and in
	// webhook notifications ("" for none).
	InstanceName     string
	PollInterval     time.Duration
	StaleMultiplier  int
	SessionIdle      time.Duration
	SessionMax       time.Duration
	StepUpWindow     time.Duration
	LoginIPPerMin    int
	LoginAcctPerHour int
	TimeZone         string
	Theme            string
	ClockFormat      string
	DateFormat       string
	TempUnit         string
	Density          string
	// The sensor history (history.go): retention in days and the sampling switches.
	HistoryRawDays, HistoryHourlyDays, HistoryDailyDays int
	SamplePSUs, SampleVoltages                          bool
	// The firmware update check (catalog.go): online check on, interval in days, notify level.
	CatalogEnabled   bool
	CatalogCheckDays int
	CatalogNotify    string
}

// General returns the file's (defaulted) General values.
func (c Config) General() General {
	return General{InstanceName: c.UI.InstanceName, PollInterval: c.Poll.Interval, StaleMultiplier: c.Poll.StaleMultiplier,
		SessionIdle: c.Auth.SessionIdle, SessionMax: c.Auth.SessionMax, StepUpWindow: c.Auth.StepUpWindow,
		LoginIPPerMin: c.RateLimit.LoginIPPerMin, LoginAcctPerHour: c.RateLimit.LoginAcctPerHour,
		TimeZone: c.UI.TimeZone, Theme: c.UI.Theme, ClockFormat: c.UI.ClockFormat, DateFormat: c.UI.DateFormat,
		TempUnit: c.UI.TemperatureUnit, Density: c.UI.Density,
		HistoryRawDays: c.History.RawDays, HistoryHourlyDays: c.History.HourlyDays, HistoryDailyDays: c.History.DailyDays,
		SamplePSUs: boolOr(c.History.SamplePSUs, true), SampleVoltages: boolOr(c.History.SampleVoltages, true),
		CatalogEnabled: boolOr(c.Firmware.Catalog.Enabled, false), CatalogCheckDays: c.Firmware.Catalog.CheckEvery,
		CatalogNotify: c.Firmware.Catalog.Notify}
}

// WithGeneral returns a copy of c carrying g (c is not modified).
func (c Config) WithGeneral(g General) Config {
	c.Poll.Interval, c.Poll.StaleMultiplier = g.PollInterval, g.StaleMultiplier
	c.Auth.SessionIdle, c.Auth.SessionMax, c.Auth.StepUpWindow = g.SessionIdle, g.SessionMax, g.StepUpWindow
	c.RateLimit.LoginIPPerMin, c.RateLimit.LoginAcctPerHour = g.LoginIPPerMin, g.LoginAcctPerHour
	c.UI.InstanceName, c.UI.TimeZone, c.UI.Theme = g.InstanceName, g.TimeZone, g.Theme
	c.UI.ClockFormat, c.UI.DateFormat, c.UI.TemperatureUnit, c.UI.Density = g.ClockFormat, g.DateFormat, g.TempUnit, g.Density
	psus, volts := g.SamplePSUs, g.SampleVoltages // fresh pointers: the original's are never shared
	c.History = HistoryConfig{RawDays: g.HistoryRawDays, HourlyDays: g.HistoryHourlyDays, DailyDays: g.HistoryDailyDays,
		SamplePSUs: &psus, SampleVoltages: &volts}
	enabled := g.CatalogEnabled
	c.Firmware.Catalog.Enabled, c.Firmware.Catalog.CheckEvery, c.Firmware.Catalog.Notify = &enabled, g.CatalogCheckDays, g.CatalogNotify
	c.Firmware.Catalog.Systems = maps.Clone(c.Firmware.Catalog.Systems)
	c.Firmware.Catalog.AllowedNetworks = slices.Clone(c.Firmware.Catalog.AllowedNetworks)
	c.FileKeys = slices.Clone(c.FileKeys)
	c.Settings.Locked = slices.Clone(c.Settings.Locked)
	c.Settings.BMCNetworks = slices.Clone(c.Settings.BMCNetworks)
	return c
}

// FileSets reports whether key (a General or Integrations key) is written in the file.
func (c Config) FileSets(key string) bool { return slices.Contains(c.FileKeys, key) }

// Locked reports whether section is listed in settings.locked.
func (c Config) Locked(section string) bool { return slices.Contains(c.Settings.Locked, section) }

// ValidateGeneral checks g against the safe ranges. minInterval is poll.min_interval
// (file-only). It returns one message per problem, naming the config key; the same
// function validates config.yaml and values saved from the browser.
func ValidateGeneral(g General, minInterval time.Duration) []string {
	var p problems
	p = validInstanceName(p, g.InstanceName)
	if g.PollInterval < minInterval {
		p = p.add("%s %v is below poll.min_interval %v", KeyPollInterval, g.PollInterval, minInterval)
	}
	p = durIn(p, KeyPollInterval, g.PollInterval, PollFloor, MaxPollInterval)
	p = intIn(p, KeyStaleMultiplier, g.StaleMultiplier, MinStaleMultiplier, MaxStaleMultiplier)
	p = durIn(p, KeySessionIdle, g.SessionIdle, MinSessionIdle, MaxSessionIdle)
	p = durIn(p, KeySessionMax, g.SessionMax, MinSessionMax, MaxSessionMax)
	if g.SessionIdle > g.SessionMax {
		p = p.add("%s %v exceeds %s %v", KeySessionIdle, g.SessionIdle, KeySessionMax, g.SessionMax)
	}
	p = durIn(p, KeyStepUpWindow, g.StepUpWindow, MinStepUpWindow, MaxStepUpWindow)
	p = intIn(p, KeyLoginIPPerMin, g.LoginIPPerMin, MinLoginIPPerMin, MaxLoginIPPerMin)
	p = intIn(p, KeyLoginAcctPerHour, g.LoginAcctPerHour, MinLoginAcctPerHour, MaxLoginAcctPerHour)
	if _, err := display.LoadZone(g.TimeZone); err != nil {
		p = p.add("%s %q must be a canonical IANA time zone such as America/New_York, or UTC", KeyTimeZone, g.TimeZone)
	}
	if _, err := display.ParseTheme(g.Theme); err != nil {
		p = p.add("%s %q is not a known theme", KeyTheme, g.Theme)
	}
	for _, f := range []struct {
		key, v string
		set    []display.Choice
	}{
		{KeyClockFormat, g.ClockFormat, display.ClockFormats()}, {KeyDateFormat, g.DateFormat, display.DateFormats()},
		{KeyTempUnit, g.TempUnit, display.TempUnits()}, {KeyDensity, g.Density, display.Densities()},
	} {
		if !display.InChoices(f.v, f.set) {
			p = p.add("%s %q must be one of %s", f.key, f.v, display.ChoiceValues(f.set))
		}
	}
	return validateCatalogGeneral(validateHistory(p, g), g)
}

func durIn(p problems, key string, v, lo, hi time.Duration) problems {
	if v < lo || v > hi {
		return p.add("%s %v must be between %v and %v", key, v, lo, hi)
	}
	return p
}

func intIn(p problems, key string, v, lo, hi int) problems {
	if v < lo || v > hi {
		return p.add("%s %d must be between %d and %d", key, v, lo, hi)
	}
	return p
}

func generalDefaults(c Config) Config {
	if c.Poll.StaleMultiplier == 0 {
		c.Poll.StaleMultiplier = DefaultStaleMultiplier
	}
	if c.RateLimit.LoginIPPerMin == 0 {
		c.RateLimit.LoginIPPerMin = DefaultLoginIPPerMin
	}
	if c.RateLimit.LoginAcctPerHour == 0 {
		c.RateLimit.LoginAcctPerHour = DefaultLoginAcctPerHour
	}
	c.UI.TimeZone = orDefault(c.UI.TimeZone, display.UTC)
	c.UI.Theme = orDefault(c.UI.Theme, string(display.DefaultTheme))
	def := display.Defaults()
	c.UI.ClockFormat = orDefault(c.UI.ClockFormat, string(def.Clock))
	c.UI.DateFormat = orDefault(c.UI.DateFormat, string(def.Date))
	c.UI.TemperatureUnit = orDefault(c.UI.TemperatureUnit, string(def.Temp))
	c.UI.Density = orDefault(c.UI.Density, string(def.Density))
	if c.Settings.BMCNetworks == nil {
		c.Settings.BMCNetworks = DefaultBMCNetworks()
	}
	c.History = historyDefaults(c.History)
	c.Firmware.Catalog = catalogDefaults(c.Firmware.Catalog)
	return c
}

func validateSettings(p problems, s SettingsConfig) problems {
	for _, sec := range s.Locked {
		switch sec {
		case SectionGeneral, SectionServers, SectionIntegrations:
		default:
			p = p.add("settings.locked %q must be one of general, servers, integrations", sec)
		}
	}
	for _, n := range s.BMCNetworks {
		pfx, err := netip.ParsePrefix(n)
		switch {
		case err != nil || pfx != pfx.Masked() || pfx.Addr().Zone() != "":
			p = p.add("settings.bmc_networks %q must be a CIDR prefix such as 10.0.0.0/8", n)
		case pfx.Bits() == 0:
			p = p.add("settings.bmc_networks %q would allow every address", n)
		}
	}
	return p
}

// fileKeys reports which GeneralKeys appear in the YAML document (before defaults).
func fileKeys(data []byte) ([]string, error) {
	var doc yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("config: decode: %w", err)
	}
	var out []string
	for _, key := range GeneralKeys() {
		if hasPath(&doc, key) {
			out = append(out, key)
		}
	}
	// GELF keys count only with a non-empty address: `address: ""` (the deploy example),
	// even next to other audit.gelf keys, leaves the whole target to the browser.
	for _, key := range IntegrationKeys() {
		if n := nodeAt(&doc, FilePath(KeyGELFAddress)); n == nil || n.Value == "" {
			break
		}
		if n := nodeAt(&doc, FilePath(key)); n != nil && n.Kind == yaml.ScalarNode && n.Value != "" {
			out = append(out, key)
		}
	}
	return out, nil
}

func hasPath(doc *yaml.Node, dotted string) bool { return nodeAt(doc, dotted) != nil }

// nodeAt is the node at a dotted path of the document, or nil.
func nodeAt(doc *yaml.Node, dotted string) *yaml.Node {
	n := doc
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	for _, part := range strings.Split(dotted, ".") {
		n = child(n, part)
		if n == nil {
			return nil
		}
	}
	return n
}

func child(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

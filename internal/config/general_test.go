package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestGeneralDefaults(t *testing.T) {
	g := mustParse(t, validYAML()).General()
	want := General{PollInterval: 60 * time.Second, StaleMultiplier: 3, SessionIdle: 30 * time.Minute,
		SessionMax: 12 * time.Hour, StepUpWindow: 5 * time.Minute, LoginIPPerMin: 5, LoginAcctPerHour: 10,
		TimeZone: "UTC", Theme: "graphite", ClockFormat: "24h", DateFormat: "iso", TempUnit: "c", Density: "compact",
		HistoryRawDays: 7, HistoryHourlyDays: 90, HistoryDailyDays: 730, SamplePSUs: true, SampleVoltages: true,
		CatalogCheckDays: 7, CatalogNotify: "urgent"}
	if g != want {
		t.Fatalf("General() = %+v, want %+v", g, want)
	}
}

func TestGeneralFromFile(t *testing.T) {
	src := strings.Replace(validYAML(), "public_url:", `ui: { time_zone: America/New_York, theme: nord }
ratelimit: { login_ip_per_min: 3, login_acct_per_hour: 20 }
settings: { locked: [general] }
public_url:`, 1)
	src = strings.Replace(src, "poll: { interval: 60s, min_interval: 30s }", "poll: { interval: 90s, min_interval: 30s, stale_multiplier: 4 }", 1)
	cfg := mustParse(t, src)
	g := cfg.General()
	if g.TimeZone != "America/New_York" || g.Theme != "nord" || g.LoginIPPerMin != 3 || g.LoginAcctPerHour != 20 ||
		g.StaleMultiplier != 4 || g.PollInterval != 90*time.Second {
		t.Fatalf("General() = %+v", g)
	}
	if !cfg.Locked(SectionGeneral) || cfg.Locked(SectionServers) {
		t.Fatalf("locked = %v", cfg.Settings.Locked)
	}
	for _, k := range []string{KeyTimeZone, KeyTheme, KeyLoginIPPerMin, KeyLoginAcctPerHour, KeyStaleMultiplier,
		KeyPollInterval, KeySessionIdle, KeySessionMax, KeyStepUpWindow} {
		if !cfg.FileSets(k) {
			t.Errorf("%s not reported as set in the file", k)
		}
	}
}

func TestFileKeysOnlyWhatIsWritten(t *testing.T) {
	src := strings.Replace(validYAML(), "  session_idle: 30m\n  session_max: 12h\n  stepup_window: 5m\n", "  session_max: 12h\n", 1)
	cfg := mustParse(t, src)
	if !slices.Equal(cfg.FileKeys, []string{KeyPollInterval, KeySessionMax,
		KeyGELFEnabled, KeyGELFAddress, KeyGELFTransport}) { // validYAML sets audit.gelf address and transport
		t.Fatalf("FileKeys = %v", cfg.FileKeys)
	}
	if cfg.FileSets(KeySessionIdle) || cfg.FileSets(KeyTimeZone) {
		t.Fatal("defaulted key reported as set")
	}
	if !slices.Equal(GeneralKeys(), []string{KeyInstanceName, KeyPollInterval, KeyStaleMultiplier, KeySessionIdle, KeySessionMax,
		KeyStepUpWindow, KeyLoginIPPerMin, KeyLoginAcctPerHour, KeyTimeZone, KeyTheme, KeyClockFormat, KeyDateFormat,
		KeyTempUnit, KeyDensity, KeyHistoryRawDays, KeyHistoryHourlyDays, KeyHistoryDailyDays, KeyHistorySamplePSUs,
		KeyHistorySampleVoltages, KeyCatalogEnabled, KeyCatalogCheckEvery, KeyCatalogNotify}) {
		t.Fatalf("GeneralKeys = %v", GeneralKeys())
	}
}

func TestDisplayDefaultsFromFile(t *testing.T) {
	src := strings.Replace(validYAML(), "public_url:",
		"ui: { clock_format: 12h, date_format: us, temperature_unit: f, density: comfortable }\npublic_url:", 1)
	cfg := mustParse(t, src)
	g := cfg.General()
	if g.ClockFormat != "12h" || g.DateFormat != "us" || g.TempUnit != "f" || g.Density != "comfortable" {
		t.Fatalf("General() = %+v", g)
	}
	for _, k := range []string{KeyClockFormat, KeyDateFormat, KeyTempUnit, KeyDensity} {
		if !cfg.FileSets(k) {
			t.Errorf("%s not reported as set in the file", k)
		}
	}
	back := cfg.WithGeneral(General{ClockFormat: "24h", DateFormat: "iso", TempUnit: "c", Density: "compact"})
	if back.UI.ClockFormat != "24h" || back.UI.TemperatureUnit != "c" {
		t.Fatalf("WithGeneral: %+v", back.UI)
	}
}

func TestGeneralRejects(t *testing.T) {
	tests := []struct{ name, from, to, want string }{
		{"poll above 10 min", "interval: 60s,", "interval: 11m,", "poll.interval"},
		{"stale multiplier low", "min_interval: 30s }", "min_interval: 30s, stale_multiplier: 1 }", "poll.stale_multiplier"},
		{"stale multiplier high", "min_interval: 30s }", "min_interval: 30s, stale_multiplier: 11 }", "poll.stale_multiplier"},
		{"idle too short", "session_idle: 30m", "session_idle: 4m", "auth.session_idle"},
		{"idle too long", "session_idle: 30m", "session_idle: 3h", "auth.session_idle"},
		{"max too long", "session_max: 12h", "session_max: 25h", "auth.session_max"},
		{"max too short", "session_max: 12h", "session_max: 30m", "auth.session_max"},
		{"stepup too long", "stepup_window: 5m", "stepup_window: 6m", "auth.stepup_window"},
		{"stepup below 1 min", "stepup_window: 5m", "stepup_window: 59s", "auth.stepup_window"},
		{"stepup 2 s (test-only window)", "stepup_window: 5m", "stepup_window: 2s", "auth.stepup_window"},
		{"login ip", "public_url:", "ratelimit: { login_ip_per_min: 11 }\npublic_url:", "ratelimit.login_ip_per_min"},
		{"login acct", "public_url:", "ratelimit: { login_acct_per_hour: 2 }\npublic_url:", "ratelimit.login_acct_per_hour"},
		{"zone", "public_url:", "ui: { time_zone: US/Eastern }\npublic_url:", "ui.time_zone"},
		{"theme", "public_url:", "ui: { theme: pink }\npublic_url:", "ui.theme"},
		{"clock", "public_url:", "ui: { clock_format: 25h }\npublic_url:", "ui.clock_format"},
		{"date", "public_url:", "ui: { date_format: eu }\npublic_url:", "ui.date_format"},
		{"temperature", "public_url:", "ui: { temperature_unit: k }\npublic_url:", "ui.temperature_unit"},
		{"density", "public_url:", "ui: { density: dense }\npublic_url:", "ui.density"},
		{"locked section", "public_url:", "settings: { locked: [everything] }\npublic_url:", "settings.locked"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := validYAML()
			if !strings.Contains(src, tc.from) {
				t.Fatalf("fixture lacks %q", tc.from)
			}
			_, err := Parse([]byte(strings.Replace(src, tc.from, tc.to, 1)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want mention of %s", err, tc.want)
			}
		})
	}
}

func TestValidateGeneralShared(t *testing.T) {
	g := mustParse(t, validYAML()).General()
	if p := ValidateGeneral(g, 30*time.Second); len(p) != 0 {
		t.Fatalf("defaults invalid: %v", p)
	}
	g.PollInterval = 45 * time.Second
	if p := ValidateGeneral(g, time.Minute); len(p) != 1 || !strings.Contains(p[0], "poll.min_interval") {
		t.Fatalf("poll below min_interval: %v", p)
	}
	g = mustParse(t, validYAML()).General()
	g.SessionIdle, g.SessionMax = 2*time.Hour, time.Hour
	if p := ValidateGeneral(g, 30*time.Second); len(p) != 1 || !strings.Contains(p[0], "exceeds") {
		t.Fatalf("idle > max: %v", p)
	}
}

func TestWithGeneral(t *testing.T) {
	cfg := mustParse(t, validYAML())
	g := cfg.General()
	g.TimeZone, g.SessionIdle = "Europe/Paris", time.Hour
	out := cfg.WithGeneral(g)
	if out.General() != g {
		t.Fatalf("WithGeneral round trip: %+v", out.General())
	}
	if cfg.UI.TimeZone != "UTC" {
		t.Fatal("WithGeneral modified its receiver")
	}
}

package config

// The sensor history (docs/tech_doc.md §39): retention of the three tiers and which
// optional sensor families are sampled. Runtime-managed in Settings → General; a key
// written in config.yaml wins there with the lock badge.

// History settings keys (runtime-managed, General section).
const (
	KeyHistoryRawDays        = "history.raw_days"
	KeyHistoryHourlyDays     = "history.hourly_days"
	KeyHistoryDailyDays      = "history.daily_days"
	KeyHistorySamplePSUs     = "history.sample_psus"
	KeyHistorySampleVoltages = "history.sample_voltages"
)

// Bounds and defaults of the history retention, in days.
const (
	MinHistoryRawDays        = 1
	MaxHistoryRawDays        = 30
	DefaultHistoryRawDays    = 7
	MinHistoryHourlyDays     = 7
	MaxHistoryHourlyDays     = 730
	DefaultHistoryHourlyDays = 90
	MinHistoryDailyDays      = 30
	MaxHistoryDailyDays      = 1825
	DefaultHistoryDailyDays  = 730
)

// HistoryConfig is the history: block. Absent switches are on.
type HistoryConfig struct {
	RawDays        int   `yaml:"raw_days"`
	HourlyDays     int   `yaml:"hourly_days"`
	DailyDays      int   `yaml:"daily_days"`
	SamplePSUs     *bool `yaml:"sample_psus"`
	SampleVoltages *bool `yaml:"sample_voltages"`
}

func historyDefaults(h HistoryConfig) HistoryConfig {
	if h.RawDays == 0 {
		h.RawDays = DefaultHistoryRawDays
	}
	if h.HourlyDays == 0 {
		h.HourlyDays = DefaultHistoryHourlyDays
	}
	if h.DailyDays == 0 {
		h.DailyDays = DefaultHistoryDailyDays
	}
	on := true
	if h.SamplePSUs == nil {
		h.SamplePSUs = &on
	}
	if h.SampleVoltages == nil {
		h.SampleVoltages = &on
	}
	return h
}

// boolOr reads an optional switch (nil: def).
func boolOr(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}

// validateHistory checks the retention bounds and that each tier is kept at least as
// long as the finer one it is built from.
func validateHistory(p problems, g General) problems {
	p = intIn(p, KeyHistoryRawDays, g.HistoryRawDays, MinHistoryRawDays, MaxHistoryRawDays)
	p = intIn(p, KeyHistoryHourlyDays, g.HistoryHourlyDays, MinHistoryHourlyDays, MaxHistoryHourlyDays)
	p = intIn(p, KeyHistoryDailyDays, g.HistoryDailyDays, MinHistoryDailyDays, MaxHistoryDailyDays)
	if g.HistoryHourlyDays < g.HistoryRawDays {
		p = p.add("%s %d must be at least %s %d", KeyHistoryHourlyDays, g.HistoryHourlyDays, KeyHistoryRawDays, g.HistoryRawDays)
	}
	if g.HistoryDailyDays < g.HistoryHourlyDays {
		p = p.add("%s %d must be at least %s %d", KeyHistoryDailyDays, g.HistoryDailyDays, KeyHistoryHourlyDays, g.HistoryHourlyDays)
	}
	return p
}

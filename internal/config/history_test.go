package config

import (
	"strings"
	"testing"
)

func TestHistoryFromFile(t *testing.T) {
	src := strings.Replace(validYAML(), "public_url:",
		"history: { raw_days: 2, hourly_days: 30, daily_days: 365, sample_psus: false }\npublic_url:", 1)
	cfg := mustParse(t, src)
	g := cfg.General()
	if g.HistoryRawDays != 2 || g.HistoryHourlyDays != 30 || g.HistoryDailyDays != 365 || g.SamplePSUs || !g.SampleVoltages {
		t.Fatalf("General() = %+v", g)
	}
	for _, k := range []string{KeyHistoryRawDays, KeyHistoryHourlyDays, KeyHistoryDailyDays, KeyHistorySamplePSUs} {
		if !cfg.FileSets(k) {
			t.Errorf("%s not reported as set in the file", k)
		}
	}
	if cfg.FileSets(KeyHistorySampleVoltages) {
		t.Error("an absent switch reported as set")
	}
	// WithGeneral stores fresh switch pointers: the copy never aliases the original.
	g.SampleVoltages = false
	back := cfg.WithGeneral(g)
	if *back.History.SampleVoltages || !*cfg.History.SampleVoltages || back.History.RawDays != 2 {
		t.Fatalf("WithGeneral: %+v / original %+v", back.History, cfg.History)
	}
}

func TestHistoryRejects(t *testing.T) {
	for name, tc := range map[string]struct{ yaml, want string }{
		"raw 0 days":         {"history: { raw_days: -1 }", KeyHistoryRawDays},
		"raw above 30":       {"history: { raw_days: 31 }", KeyHistoryRawDays},
		"hourly below 7":     {"history: { hourly_days: 6 }", KeyHistoryHourlyDays},
		"hourly above 730":   {"history: { hourly_days: 731, daily_days: 1825 }", KeyHistoryHourlyDays},
		"daily below 30":     {"history: { daily_days: 29 }", KeyHistoryDailyDays},
		"daily above 1825":   {"history: { daily_days: 1826 }", KeyHistoryDailyDays},
		"hourly below raw":   {"history: { raw_days: 20, hourly_days: 10 }", "must be at least history.raw_days"},
		"daily below hourly": {"history: { hourly_days: 400, daily_days: 300 }", "must be at least history.hourly_days"},
		"unknown key":        {"history: { tsdb: true }", "tsdb"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(strings.Replace(validYAML(), "public_url:", tc.yaml+"\npublic_url:", 1)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want mention of %s", err, tc.want)
			}
		})
	}
}

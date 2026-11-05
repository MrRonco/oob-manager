package ui

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/display"
	"oob-manager/internal/history"
	"oob-manager/internal/history/svg"
	"oob-manager/internal/store"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/*.svg")

// goldenPanel is a fixed History panel: two series over 24 h, the focus with a gap and
// a warning band in reach, one critical marker and a maintenance span.
func goldenPanel() histPanel {
	t0 := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	step := 10 * time.Minute
	mk := func(base float64, skip int) []store.Bucket {
		var out []store.Bucket
		for i := 0; i < 144; i++ {
			if skip > 0 && i >= skip && i < skip+12 {
				continue
			}
			v := base + float64(i%24)/4
			out = append(out, store.Bucket{Start: t0.Add(time.Duration(i) * step), Min: v - 1, Avg: v, Max: v + 1.5, N: 10})
		}
		return out
	}
	tf := fmtIn(time.UTC)
	in := svg.Input{From: t0, To: t0.Add(24 * time.Hour), Loc: time.UTC, Format: histUnitOf(store.UnitCelsius, display.Celsius).tick,
		XLabel: tf.axisLabel,
		Series: []svg.Series{{Buckets: mk(40, 0), Step: step, Title: "CPU2 Temp"},
			{Buckets: mk(45, 60), Step: step, Focus: true, Title: "CPU1 Temp"}},
		Bands: svg.Bands{Warn: 52, HasWarn: true, Crit: 90, HasCrit: true},
		Marks: []svg.Mark{{At: t0.Add(15 * time.Hour), Critical: true, Title: "15:00 PSU 2 lost input"}},
		Spans: []svg.Span{{From: t0.Add(2 * time.Hour), To: t0.Add(4 * time.Hour), Title: "Maintenance 02:00 to 04:00"}}}
	return histPanel{ID: "h-temp", Title: "Temperatures", Unit: "°C", Chart: svg.Build(in),
		ChartTitle: "Temperatures: CPU1 Temp, last 24 hours", ChartDesc: "CPU1 Temp: minimum 44.0 °C, average 47.9 °C, maximum 52.2 °C."}
}

func renderPartial(t *testing.T, name string, data any) string {
	t.Helper()
	rd, err := newRenderer()
	must(t, err)
	var buf bytes.Buffer
	must(t, rd.pages[pageHistory].ExecuteTemplate(&buf, name, data))
	return strings.TrimSpace(buf.String()) + "\n"
}

func golden(t *testing.T, file, got string) {
	t.Helper()
	path := filepath.Join("testdata", file)
	if *updateGolden {
		must(t, os.WriteFile(path, []byte(got), 0o600))
	}
	want, err := os.ReadFile(path) // #nosec G304 -- a fixed test file
	must(t, err)
	if string(want) != got {
		t.Fatalf("%s differs (go test -run Golden -update):\n%s", path, got)
	}
}

// TestGoldenHistorySVG pins the chart and sparkline markup: deterministic numbers, one
// <title> and <desc> per chart, no style attribute, no script, one path command per
// bucket.
func TestGoldenHistorySVG(t *testing.T) {
	t.Parallel()
	chart := renderPartial(t, "histchart", goldenPanel())
	golden(t, "history_chart.svg", chart)
	t0 := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	var bs []store.Bucket
	for i := 0; i < 48; i++ {
		bs = append(bs, store.Bucket{Start: t0.Add(time.Duration(i) * history.SparkStep), Min: 1, Avg: float64(200 + i%7*5), Max: 300, N: 30})
	}
	sp := svg.Sparkline(bs, t0, t0.Add(24*time.Hour), history.SparkStep)
	spark := renderPartial(t, "sparkline", sparkView{ID: "sp-draw", Href: "/servers/r730xd/history?range=24h#h-power",
		ViewBox: sp.ViewBox, D: sp.D, Title: "Power draw, last 24 hours", Desc: "Minimum 200 W, average 214 W, maximum 230 W."})
	golden(t, "history_sparkline.svg", spark)
	for name, out := range map[string]string{"chart": chart, "sparkline": spark} {
		if strings.Contains(out, " style=") || strings.Contains(out, "<script") ||
			strings.Count(out, "<title id=") != 1 || strings.Count(out, "<desc id=") != 1 {
			t.Errorf("%s markup breaks the rules:\n%s", name, out)
		}
	}
	if n := strings.Count(chart, `class="ser ser-focus"`); n != 1 {
		t.Errorf("%d focused lines", n)
	}
}

func TestHistoryUnits(t *testing.T) {
	t.Parallel()
	f := histUnitOf(store.UnitCelsius, display.Fahrenheit)
	if f.Symbol != "°F" || f.text(100) != "212.0 °F" || f.tick(212) != "212" {
		t.Errorf("°F: %+v %s %s", f, f.text(100), f.tick(212))
	}
	if bs := f.buckets([]store.Bucket{{Min: 0, Avg: 10, Max: 100}}); bs[0].Min != 32 || bs[0].Max != 212 {
		t.Errorf("converted buckets %+v", bs)
	}
	for u, want := range map[store.SensorUnit]string{store.UnitRPM: "7440 RPM", store.UnitPercent: "7440 %",
		store.UnitWatts: "7440 W", store.UnitVolts: "7440.00 V"} {
		if got := histUnitOf(u, display.Celsius).text(7440); got != want {
			t.Errorf("%s: %s", u, got)
		}
	}
	c := histUnitOf(store.UnitCelsius, display.Celsius)
	if bs := []store.Bucket{{Avg: 1}}; &c.buckets(bs)[0] != &bs[0] {
		t.Error("Celsius buckets are used as they are")
	}
	tf := fmtIn(time.UTC)
	at := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	if tf.axisLabel(at, false) != "Oct 20" || tf.axisLabel(at.Add(time.Hour), false) != "01:00" ||
		tf.bucketTime(at, 24*time.Hour, at) != "2026-10-20 UTC" ||
		fmtIn(time.FixedZone("EDT", -4*3600)).bucketTime(at, 24*time.Hour, at) != "2026-10-20 UTC" {
		t.Error("axis and table times")
	}
	if fmtSize(38_000_000) != "38 MB" || fmtSize(1_500_000_000) != "1.5 GB" || fmtSize(5_000) != "5 kB" ||
		fmtCount(1_234_567) != "1.2 M" || fmtCount(48_000) != "48 k" || fmtCount(950) != "950" {
		t.Error("size and count formats")
	}
}

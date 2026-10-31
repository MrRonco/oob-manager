package ui

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/display"
	"oob-manager/internal/fleet"
	"oob-manager/internal/history"
	"oob-manager/internal/history/svg"
	"oob-manager/internal/store"
)

// maxChartSeries is the most lines one chart draws; the rest are "Also recorded", of
// which maxAlso are listed as links (a BMC with hundreds of sensors cannot bloat the page).
const (
	maxChartSeries = 16
	maxAlso        = 48
)

// panelSpec is one History panel: the sensor kinds it draws.
type panelSpec struct {
	ID, Title string
	Kinds     []store.SensorKind
}

func panelSpecs() []panelSpec {
	return []panelSpec{
		{"h-temp", "Temperatures", []store.SensorKind{store.SensorTemp}},
		{"h-fan", "Fans", []store.SensorKind{store.SensorFan}},
		{"h-power", "Power draw", []store.SensorKind{store.SensorPower}},
		{"h-psu", "Power supplies", []store.SensorKind{store.SensorPSUIn, store.SensorPSUOut}},
		{"h-volt", "Voltage rails", []store.SensorKind{store.SensorVolt}},
	}
}

// legendItem is one sensor of a panel: a focus link (no script needed to focus).
type legendItem struct {
	Label, Href string
	Current     bool
}

// histRow is one row of a panel's data table (the chart's points as text, 1.1.1).
type histRow struct {
	When, ISO, Min, Avg, Max, N string
}

// histFocus is the focused series of a panel.
type histFocus struct {
	Label, Min, Avg, Max, Samples string
	Has                           bool
	CSVHref, RawHref              string
}

// histPanel is one kind's chart with its legend, numbers and table.
type histPanel struct {
	ID, Title, Unit string
	ChartTitle      string
	ChartDesc       string
	Chart           svg.Chart
	Legend          []legendItem
	Also            []legendItem
	AlsoMore        int // recorded sensors beyond the Also list
	Focus           histFocus
	CoarseNote      string
	Rows            []histRow
	Bands           string // the threshold bands, as text
}

// histCtx is what every panel of one page shares.
type histCtx struct {
	serverID string
	plan     history.Plan
	now      time.Time
	tf       timeFmt
	temp     display.TempUnit
	focus    string
	snap     bmc.Snapshot
	marks    []svg.Mark
	spans    []svg.Span
	nMarks   int
}

// panelGroup is one panel's spec and series.
type panelGroup struct {
	spec   panelSpec
	series []history.Series
}

// groupPanels splits the series between the panels (one per kind group and unit), in
// the store's display order; panels without a series are left out.
func groupPanels(series []history.Series) []panelGroup {
	var out []panelGroup
	for _, ps := range panelSpecs() {
		var units []store.SensorUnit
		for _, sr := range series {
			if slices.Contains(ps.Kinds, sr.Key.Kind) && !slices.Contains(units, sr.Key.Unit) {
				units = append(units, sr.Key.Unit)
			}
		}
		for _, u := range units {
			spec := ps
			if len(units) > 1 {
				spec.ID, spec.Title = ps.ID+"-"+string(u), ps.Title+" ("+histUnitOf(u, display.Celsius).Symbol+")"
			}
			var part []history.Series
			for _, sr := range series {
				if slices.Contains(ps.Kinds, sr.Key.Kind) && sr.Key.Unit == u {
					part = append(part, sr)
				}
			}
			out = append(out, panelGroup{spec, part})
		}
	}
	return out
}

// focusIndex is the focused series of a panel: the requested key when it is here, else
// the first.
func focusIndex(series []history.Series, focus string) int {
	if i := slices.IndexFunc(series, func(s history.Series) bool { return s.Key.Key == focus }); i >= 0 {
		return i
	}
	return 0
}

// charted is the series a chart draws (at most maxChartSeries, the focus always among
// them) and the rest.
func charted(series []history.Series, fi int) ([]history.Series, []history.Series) {
	if len(series) <= maxChartSeries {
		return series, nil
	}
	drawn := slices.Clone(series[:maxChartSeries])
	rest := slices.Clone(series[maxChartSeries:])
	if fi >= maxChartSeries {
		drawn[maxChartSeries-1], rest[fi-maxChartSeries] = series[fi], series[maxChartSeries-1]
	}
	return drawn, rest
}

func (hc histCtx) focusHref(key, panelID string) string {
	q := url.Values{}
	q.Set("range", string(hc.plan.Range))
	q.Set("focus", key)
	return "/servers/" + hc.serverID + "/history?" + q.Encode() + "#" + panelID
}

func (hc histCtx) csvHref(key string, raw bool) string {
	q := url.Values{}
	q.Set("sensor", key)
	q.Set("range", string(hc.plan.Range))
	if raw {
		q.Set("raw", "1")
	}
	return "/servers/" + hc.serverID + "/history.csv?" + q.Encode()
}

// buildPanel is one panel: the chart of up to 16 series (the focus accented with its
// envelope and threshold bands), the legend, the focus's numbers and its data table.
func (hc histCtx) buildPanel(spec panelSpec, series []history.Series) histPanel {
	fi := focusIndex(series, hc.focus)
	f := series[fi]
	u := histUnitOf(f.Key.Unit, hc.temp)
	p := histPanel{ID: spec.ID, Title: spec.Title, Unit: u.Symbol}
	drawn, rest := charted(series, fi)
	in := svg.Input{From: hc.plan.From, To: hc.plan.To, Loc: hc.tf.loc, Marks: hc.marks, Spans: hc.spans,
		Format: u.tick, XLabel: hc.tf.axisLabel}
	for _, sr := range drawn {
		focus := sr.Key.Key == f.Key.Key
		in.Series = append(in.Series, svg.Series{Buckets: u.buckets(sr.Buckets), Step: hc.plan.Step, Focus: focus,
			Width: bucketWidth(sr, hc.plan), Title: history.Label(sr.Key)})
		p.Legend = append(p.Legend, legendItem{Label: history.Label(sr.Key), Href: hc.focusHref(sr.Key.Key, spec.ID), Current: focus})
	}
	for i, sr := range rest {
		if i == maxAlso {
			p.AlsoMore = len(rest) - maxAlso
			break
		}
		p.Also = append(p.Also, legendItem{Label: history.Label(sr.Key), Href: hc.focusHref(sr.Key.Key, spec.ID)})
	}
	in.Bands, p.Bands = hc.bands(f.Key, u)
	p.Chart = svg.Build(in)
	p.Focus = hc.focusOf(f, u)
	p.ChartTitle = spec.Title + ": " + history.Label(f.Key) + ", last " + hc.plan.Range.Label()
	p.ChartDesc = hc.describe(f, u, len(drawn))
	p.CoarseNote = hc.coarseNote(f)
	for _, b := range f.Buckets {
		p.Rows = append(p.Rows, histRow{When: hc.tf.bucketTime(b.Start, hc.plan.Step, hc.now),
			ISO: b.Start.UTC().Format(time.RFC3339), Min: u.num(b.Min), Avg: u.num(b.Avg), Max: u.num(b.Max),
			N: fmt.Sprint(b.N)})
	}
	return p
}

// bucketWidth is how wide each bucket of sr is: one plan step, or the hour or day of
// the coarser tier that served it (it is drawn at its own middle, and the line bridges
// gaps by its own width).
func bucketWidth(sr history.Series, p history.Plan) func(store.Bucket) time.Duration {
	return func(b store.Bucket) time.Duration { return sr.BucketEnd(b, p).Sub(b.Start) }
}

func (hc histCtx) focusOf(f history.Series, u histUnit) histFocus {
	fc := histFocus{Label: history.Label(f.Key), Has: f.Summary.Has(), CSVHref: hc.csvHref(f.Key.Key, false)}
	if hc.plan.Range == history.Range24h || hc.plan.Range == history.Range7d {
		fc.RawHref = hc.csvHref(f.Key.Key, true)
	}
	if fc.Has {
		fc.Min, fc.Avg, fc.Max = u.text(f.Summary.Min), u.text(f.Summary.Avg), u.text(f.Summary.Max)
		fc.Samples = plural(int(f.Summary.N), "sample", "samples")
	}
	return fc
}

// describe is the chart's <desc>: the focus's minimum, average and maximum and the
// number of events drawn.
func (hc histCtx) describe(f history.Series, u histUnit, lines int) string {
	if !f.Summary.Has() {
		return "No readings of " + history.Label(f.Key) + " in this period."
	}
	d := fmt.Sprintf("%s: minimum %s, average %s, maximum %s.", history.Label(f.Key), u.text(f.Summary.Min),
		u.text(f.Summary.Avg), u.text(f.Summary.Max))
	if lines > 1 {
		d += fmt.Sprintf(" %d sensors drawn.", lines)
	}
	return d + " " + plural(hc.nMarks, "event", "events") + " marked. The data table below lists every point."
}

func (hc histCtx) coarseNote(f history.Series) string {
	tier, until, ok := f.Coarse(hc.plan)
	if !ok {
		return ""
	}
	what := "Hourly"
	if tier == store.TierDaily {
		what = "Daily"
	}
	return what + " averages before " + hc.tf.short(until, hc.now) + ": older readings are kept as summaries only."
}

// bands are the focused temperature's warning and critical thresholds from the current
// snapshot (the history keeps no thresholds), converted to the viewer's unit.
func (hc histCtx) bands(k store.SensorKey, u histUnit) (svg.Bands, string) {
	if k.Kind != store.SensorTemp {
		return svg.Bands{}, ""
	}
	for _, t := range hc.snap.Temperatures() {
		if fleet.SampleKey(fleet.KeyTemperature, t.ID, t.Name) != k.Key {
			continue
		}
		b := svg.Bands{Warn: u.conv(t.WarnAbove.Value), HasWarn: t.WarnAbove.Valid,
			Crit: u.conv(t.CritAbove.Value), HasCrit: t.CritAbove.Valid}
		var text []string
		if b.HasWarn {
			text = append(text, "warning above "+u.text(t.WarnAbove.Value))
		}
		if b.HasCrit {
			text = append(text, "critical above "+u.text(t.CritAbove.Value))
		}
		return b, strings.Join(text, ", ")
	}
	return svg.Bands{}, ""
}

package ui

import (
	"context"
	"strconv"

	"oob-manager/internal/authz"
	"oob-manager/internal/history"
	"oob-manager/internal/history/svg"
	"oob-manager/internal/store"
)

// maxRecorderRows bounds the Overview's flight recorder (one history read per row); the
// table on the Servers page lists every server.
const maxRecorderRows = 24

// recorderView is the desktop fleet view of the Overview (round-2 slice C, borrowed from
// direction C): one row per server, worst first, each server's hottest sensor over the
// last 24 hours on one shared time axis. Server-rendered SVG from the sensor history's
// sparkline plan (30-minute buckets of raw rows); no script. Every row has a text
// summary, and a data table repeats the numbers.
type recorderView struct {
	Ticks []recTick
	Rows  []recRow
	More  int // servers beyond maxRecorderRows (in the Servers table)
}

type recTick struct {
	Label string
	Pct   int
}

// recRow is one server's row. Without history for its hottest sensor, NoHistory is set
// and only the text is drawn.
type recRow struct {
	ID, Name, Sensor, Now, Issue string
	Health                       healthView
	Fresh                        freshness
	ViewBox, Line, Area          string
	Gaps                         []svg.Rect
	Min, Avg, Max, Without       string
	Desc                         string
	NoHistory                    bool
}

// recorderFor builds the recorder from the rows shown on the Overview; nil when the
// history is off or the viewer may not see it. Each server costs one read of its sensor
// list; the series of every row not in the recorder cache come from one Chart call.
func (s *server) recorderFor(ctx context.Context, rows []summaryRow, sess session) *recorderView {
	if !s.historyOn() || s.d.Authorize(sess.id.Principal(), authz.ViewHistory, true) != nil || len(rows) == 0 {
		return nil
	}
	p := history.SparkPlan(s.d.History.Now())
	rv := &recorderView{}
	tf := sess.tf()
	for _, t := range svg.AxisTicks(p.From, p.To, tf.loc) {
		if t.Pct < 4 || t.Pct > 88 { // keep clear of the row's edges and the "now" label
			continue
		}
		rv.Ticks = append(rv.Ticks, recTick{Label: t.At.In(tf.loc).Format(tf.hm()), Pct: t.Pct})
	}
	if len(rows) > maxRecorderRows {
		rv.More, rows = len(rows)-maxRecorderRows, rows[:maxRecorderRows]
	}
	unit := sess.view.Temp
	keys := make([]*store.SensorKey, len(rows))
	var want []store.SensorKey
	for i, row := range rows {
		if ks, ok := s.historyKeys(ctx, row.ID); ok {
			if k, found := keyByName(ks, row.HottestKey); found {
				keys[i] = &k
				if _, hit := s.recCache.get(recCacheKey{row.ID, k.Key, string(unit), p.From}, s.d.Now()); !hit {
					want = append(want, k)
				}
			}
		}
	}
	fetched := s.recSeries(ctx, want, p)
	for i, row := range rows {
		rv.Rows = append(rv.Rows, s.recRowOf(row, keys[i], fetched, p, sess))
	}
	return rv
}

// recSeries reads want in one Chart call; a failure is logged and those rows say so.
func (s *server) recSeries(ctx context.Context, want []store.SensorKey, p history.Plan) map[string]history.Series {
	out := map[string]history.Series{}
	if len(want) == 0 {
		return out
	}
	series, err := s.d.History.Chart(ctx, want, p)
	if err != nil {
		s.d.Logger.Warn("ui recorder failed", "err", err)
		return out
	}
	for _, sr := range series {
		out[sr.Key.ServerID+"/"+sr.Key.Key] = sr
	}
	return out
}

func (s *server) recRowOf(row summaryRow, key *store.SensorKey, fetched map[string]history.Series, p history.Plan,
	sess session) recRow {
	r := recRow{ID: row.ID, Name: row.Name, Health: row.Health, Fresh: row.Fresh, Issue: row.Issue,
		Sensor: row.HottestName, NoHistory: true}
	if row.Hottest.Value != "" && !row.Fresh.Stale && !row.HostDown {
		r.Now = row.Hottest.Value + " " + row.Hottest.Unit
	}
	if key == nil {
		r.Desc = row.Name + ": no history recorded yet."
		return r
	}
	ck := recCacheKey{row.ID, key.Key, string(sess.view.Temp), p.From}
	g, hit := s.recCache.get(ck, s.d.Now())
	if !hit {
		sr, ok := fetched[key.ServerID+"/"+key.Key]
		if !ok || len(sr.Buckets) == 0 {
			r.Desc = row.Name + ": no readings in the last 24 hours."
			return r
		}
		g = recGeometry(sr, p, histUnitOf(sr.Key.Unit, sess.view.Temp))
		s.recCache.put(ck, g, s.d.Now())
	}
	r.NoHistory, r.ViewBox, r.Line, r.Area, r.Gaps = false, g.ViewBox, g.Line, g.Area, g.Gaps
	r.Sensor, r.Min, r.Avg, r.Max, r.Without = g.Sensor, g.Min, g.Avg, g.Max, g.Without
	r.Desc = row.Name + ", " + r.Sensor + ", last 24 hours: minimum " + r.Min + ", average " + r.Avg +
		", maximum " + r.Max + "; " + lowerFirst(r.Without) + "."
	return r
}

// recGeo is a row's drawing and numbers, the part the recorder cache keeps.
type recGeo struct {
	ViewBox, Line, Area, Sensor, Min, Avg, Max, Without string
	Gaps                                                []svg.Rect
}

func recGeometry(sr history.Series, p history.Plan, u histUnit) recGeo {
	g := svg.RecorderRow(u.buckets(sr.Buckets), p.From, p.To, p.Step)
	sm := sr.Summary
	return recGeo{ViewBox: g.ViewBox, Line: g.Line, Area: g.Area, Gaps: g.Gaps, Sensor: history.Label(sr.Key),
		Min: u.text(sm.Min), Avg: u.text(sm.Avg), Max: u.text(sm.Max), Without: withoutReadings(p, len(sr.Buckets))}
}

// withoutReadings says how much of the window had no bucket ("No gaps", "2 h 30 min
// without readings").
func withoutReadings(p history.Plan, have int) string {
	n := int(p.To.Sub(p.From)/p.Step) - have
	if n <= 0 {
		return "No gaps"
	}
	mins := n * int(p.Step.Minutes())
	h, m := mins/60, mins%60
	out := ""
	if h > 0 {
		out = strconv.Itoa(h) + " h"
	}
	if m > 0 {
		out = joinSpace(out, strconv.Itoa(m)+" min")
	}
	return out + " without readings"
}

func joinSpace(a, b string) string {
	if a == "" {
		return b
	}
	return a + " " + b
}

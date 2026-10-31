package ui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"oob-manager/internal/authz"
	"oob-manager/internal/history"
	"oob-manager/internal/history/svg"
	"oob-manager/internal/store"
)

// maxFocusLen bounds the focus parameter (a sensor key; longer is ignored).
const maxFocusLen = store.MaxSensorKeyLen

// rangeLink is one entry of the range picker (links: no script, no form).
type rangeLink struct {
	Label, Href string
	Current     bool
}

// markerRow is one event of the period as text (the chart's markers, repeated).
type markerRow struct {
	When, ISO, Text, Log, Href string
	Severity                   healthView
	Acked                      bool
}

// historyView is the History tab.
type historyView struct {
	Head       serverHead
	Nav        serverNav
	Ranges     []rangeLink
	RangeLabel string
	Panels     []histPanel
	Marks      []markerRow
	MoreMarks  int
	Spans      []string
	ClockNote  string
	Empty      bool
	ExportAll  string // "every sensor" CSV, for operators
	Notice     string
}

func (s *server) historyPage(w http.ResponseWriter, r *http.Request, sess session) {
	if !s.historyOn() {
		s.historyMissing(w, r)
		return
	}
	v, ok := s.lookup(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	rng, ok := history.ParseRange(q.Get("range"))
	if !ok {
		s.errorPage(w, r, http.StatusBadRequest, "Unknown range. Pick one of 24 hours, 7 days, 30 days or 1 year.")
		return
	}
	focus := q.Get("focus")
	if len(focus) > maxFocusLen {
		focus = ""
	}
	hv := s.historyViewOf(r.Context(), v, sess, history.PlanFor(rng, s.d.History.Now()), focus)
	d := s.serverLayout(sess, v, v.Name+": history", "History", hv)
	s.render(w, r, http.StatusOK, pageHistory, d)
}

func (s *server) historyViewOf(ctx context.Context, v ServerView, sess session, p history.Plan, focus string) historyView {
	hv := historyView{Head: s.headFor(v, sess).tab("history"), Nav: s.navFor(v, sess, "history"),
		Ranges: rangeLinks(v.ID, p.Range, focus), RangeLabel: p.Range.Label()}
	keys, ok := s.historyKeys(ctx, v.ID)
	if !ok {
		hv.Notice = "The history could not be read. Try again in a moment."
		return hv
	}
	if len(keys) == 0 {
		hv.Empty = true
		return hv
	}
	series, err := s.d.History.Chart(ctx, keys, p)
	if err != nil {
		s.d.Logger.Warn("ui history chart failed", "server", v.ID, "err", err)
		hv.Notice = "The history could not be read. Try again in a moment."
		return hv
	}
	now, tf := s.d.History.Now(), sess.tf()
	marks := s.historyMarkers(ctx, v, p, now)
	hc := histCtx{serverID: v.ID, plan: p, now: now, tf: tf, temp: sess.view.Temp, focus: focus, snap: v.Snapshot,
		nMarks: len(marks.Marks)}
	hc.marks, hc.spans = chartMarks(marks, tf, now)
	for _, g := range groupPanels(series) {
		hv.Panels = append(hv.Panels, hc.buildPanel(g.spec, g.series))
	}
	hv.Marks, hv.MoreMarks, hv.Spans = s.markerRows(v.ID, marks, tf, now), marks.More, spanTexts(marks.Spans, tf, now)
	hv.ClockNote = s.clockNote(ctx, p, tf, now)
	if s.d.Authorize(sess.id.Principal(), authz.ExportHistoryAll, true) == nil {
		q := url.Values{"all": {"1"}, "range": {string(p.Range)}}
		hv.ExportAll = "/servers/" + v.ID + "/history.csv?" + q.Encode()
	}
	return hv
}

func rangeLinks(id string, cur history.Range, focus string) []rangeLink {
	out := make([]rangeLink, 0, len(history.Ranges()))
	for _, r := range history.Ranges() {
		q := url.Values{"range": {string(r)}}
		if focus != "" {
			q.Set("focus", focus)
		}
		out = append(out, rangeLink{Label: r.Label(), Href: "/servers/" + id + "/history?" + q.Encode(), Current: r == cur})
	}
	return out
}

// historyMarkers reads the overlay: the cached SEL and Lifecycle entries (never the BMC)
// with their acknowledgements, the audit rows, and the active maintenance window when
// it started before the range.
func (s *server) historyMarkers(ctx context.Context, v ServerView, p history.Plan, now time.Time) history.Markers {
	var logs []history.LogEntry
	for _, kind := range []LogKind{LogSEL, LogLifecycle} {
		log, err := s.d.Fleet.Events(ctx, v.ID, kind)
		if err != nil {
			continue
		}
		for _, e := range log.Entries() {
			_, acked := s.acked(v.ID, kind, e)
			logs = append(logs, history.LogEntry{Event: e, Log: logLabel(kind), Acked: acked})
		}
	}
	m, err := s.d.History.Overlay(ctx, v.ID, p, logs)
	if err != nil {
		s.d.Logger.Warn("ui history overlay failed", "server", v.ID, "err", err)
		m = history.Collect(nil, history.FromLogs(logs, p.From, p.To))
	}
	if s.d.Maintenance != nil {
		if w, ok := s.d.Maintenance.Active(v.ID); ok && w.StartsAt.Before(p.From) && !openSpan(m.Spans) {
			m.Spans = append(m.Spans, history.Span{From: p.From, To: minTime(p.To, now), Open: true})
		}
	}
	return m
}

func openSpan(spans []history.Span) bool {
	for _, sp := range spans {
		if sp.Open {
			return true
		}
	}
	return false
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func chartMarks(m history.Markers, tf timeFmt, now time.Time) ([]svg.Mark, []svg.Span) {
	marks := make([]svg.Mark, 0, len(m.Marks))
	for _, mk := range m.Marks {
		marks = append(marks, svg.Mark{At: mk.At, Critical: mk.Critical, Title: tf.short(mk.At, now) + " " + mk.Text})
	}
	spans := make([]svg.Span, 0, len(m.Spans))
	for _, sp := range m.Spans {
		spans = append(spans, svg.Span{From: sp.From, To: sp.To, Title: "Maintenance " + spanText(sp, tf, now)})
	}
	return marks, spans
}

func spanText(sp history.Span, tf timeFmt, now time.Time) string {
	if sp.Open {
		return "since " + tf.short(sp.From, now)
	}
	return tf.short(sp.From, now) + " to " + tf.short(sp.To, now)
}

func spanTexts(spans []history.Span, tf timeFmt, now time.Time) []string {
	out := make([]string, 0, len(spans))
	for _, sp := range spans {
		out = append(out, "Maintenance "+spanText(sp, tf, now))
	}
	return out
}

// markerRows lists the events newest first; log entries link to the server's logs.
func (s *server) markerRows(id string, m history.Markers, tf timeFmt, now time.Time) []markerRow {
	out := make([]markerRow, 0, len(m.Marks))
	for i := len(m.Marks) - 1; i >= 0; i-- {
		mk := m.Marks[i]
		row := markerRow{When: tf.short(mk.At, now), ISO: mk.At.UTC().Format(time.RFC3339), Text: mk.Text, Acked: mk.Acked,
			Severity: healthView{Label: "Event", Class: "info"}}
		switch {
		case mk.Kind == history.MarkLog && mk.Critical:
			row.Severity, row.Log, row.Href = healthView{Label: "Critical", Class: "crit"}, mk.Log, logHref(id, mk.Log)
		case mk.Kind == history.MarkLog:
			row.Severity, row.Log, row.Href = healthView{Label: "Warning", Class: "warn"}, mk.Log, logHref(id, mk.Log)
		}
		out = append(out, row)
	}
	return out
}

func logHref(id, log string) string {
	if log == logLabel(LogLifecycle) {
		return "/servers/" + id + "/events?log=lifecycle"
	}
	return "/servers/" + id + "/events"
}

// clockNote explains a clock step: one back inside the range (samples may overlap), and
// a retention clock behind the wall clock (a forward step or a restart after downtime:
// old readings are being deleted gradually).
func (s *server) clockNote(ctx context.Context, p history.Plan, tf timeFmt, now time.Time) string {
	var notes []string
	jump, err := s.d.History.ClockJump(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		s.d.Logger.Warn("ui history clock jump read failed", "err", err)
	}
	if !jump.IsZero() && !jump.Before(p.From) {
		notes = append(notes, "The clock moved back on "+tf.short(jump, now)+"; samples around that time may overlap.")
	}
	st := s.d.History.Status()
	if lag, ok := history.Lagging(st, now); ok {
		why := "a restart after downtime, or the clock moved forward"
		if !st.LastForwardJump.IsZero() {
			why += " (last seen " + tf.short(st.LastForwardJump, now) + ")"
		}
		notes = append(notes, fmt.Sprintf("The clock is %s ahead of the history's own clock (%s). Old readings are "+
			"deleted gradually, at most two hours' worth an hour, so a wrong clock cannot erase the history.", fmtLag(lag), why))
	}
	return strings.Join(notes, " ")
}

// fmtLag is a lag as "5 h" or "3 days".
func fmtLag(d time.Duration) string {
	if d < 48*time.Hour {
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours())/24)
}

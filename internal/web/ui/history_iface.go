package ui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"oob-manager/internal/authz"
	"oob-manager/internal/csvx"
	"oob-manager/internal/history"
	"oob-manager/internal/store"
)

// History is the sensor history (*history.Service, tech_doc §39). Every read is served
// from the database's read-only connection: a History page, a sparkline or an export
// never reaches a BMC and never holds the writer.
type History interface {
	Now() time.Time
	Sensors(ctx context.Context, serverID string) ([]store.SensorKey, error)
	Chart(ctx context.Context, keys []store.SensorKey, p history.Plan) ([]history.Series, error)
	Overlay(ctx context.Context, serverID string, p history.Plan, logs []history.LogEntry) (history.Markers, error)
	ClockJump(ctx context.Context) (time.Time, error)
	// Status is the janitor's last pass (Settings → General shows the size).
	Status() history.Status
	PrepareExport(ctx context.Context, e history.Export) (history.PreparedExport, error)
	WriteCSV(ctx context.Context, w io.Writer, flush func(), p history.PreparedExport) error
}

// historyExportRate limits history CSV exports per user (a separate bucket from the
// firmware export's); historyDenyRate audits one refusal per user, action and class a
// minute.
var (
	historyExportRate = RateLimit{Events: 6, Per: time.Minute}
	historyDenyRate   = RateLimit{Events: 1, Per: time.Minute}
)

// denyCoalesced audits a refusal unless the same user had the same refusal audited in
// the last minute (the response is the same either way).
func (s *server) denyCoalesced(r *http.Request, sess session, action authz.Action, class string) {
	if ok, _ := s.historyDenyLimit.allow("user:" + sess.id.User.ID + "/" + string(action) + "/" + class); ok {
		s.deny(r, sess, action, class)
	}
}

// historyRoutes: the History tab and its CSV (viewer; every sensor at once: operator).
// Downloads are plain reads, not audited (plan 02 decision); refusals are.
func (s *server) historyRoutes(mux *http.ServeMux) {
	mux.Handle("GET /servers/{id}/history", s.page(authz.ViewHistory, s.historyPage))
	mux.Handle("GET /servers/{id}/history.csv", s.page(authz.ExportHistory, s.historyCSV))
}

// historyOn reports whether the history is wired.
func (s *server) historyOn() bool { return s.d.History != nil }

func (s *server) historyMissing(w http.ResponseWriter, r *http.Request) {
	s.errorPage(w, r, http.StatusNotFound, "The sensor history is not available in this installation.")
}

// historyKeys lists a server's sensors; a failure is logged and reads as none.
func (s *server) historyKeys(ctx context.Context, id string) ([]store.SensorKey, bool) {
	keys, err := s.d.History.Sensors(ctx, id)
	if err != nil {
		s.d.Logger.Warn("ui history sensors failed", "server", id, "err", err)
		return nil, false
	}
	return keys, true
}

// keyByName finds a sensor by its key ("" or unknown: false).
func keyByName(keys []store.SensorKey, key string) (store.SensorKey, bool) {
	if i := slices.IndexFunc(keys, func(k store.SensorKey) bool { return k.Key == key }); i >= 0 {
		return keys[i], true
	}
	return store.SensorKey{}, false
}

// historyCSV exports one sensor (sensor=…) or, for operators, every sensor (all=1) of a
// server over a range, bucketed like the chart or raw (raw=1). Too many rows is a 413
// page before anything is written; the download itself streams.
func (s *server) historyCSV(w http.ResponseWriter, r *http.Request, sess session) {
	if !s.historyOn() {
		s.historyMissing(w, r)
		return
	}
	v, ok := s.lookup(w, r)
	if !ok {
		return
	}
	// The rate limit comes first and repeated refusals are audited once a minute per
	// user and kind, so a loop of refused requests cannot flood the audit chain.
	if ok, wait := s.historyExportLimit.allow("user:" + sess.id.User.ID); !ok {
		s.denyCoalesced(r, sess, authz.ExportHistory, "rate_limited")
		setRetryAfter(w, wait)
		s.errorPage(w, r, http.StatusTooManyRequests, "Too many exports in a short time. "+tryAgainIn(wait))
		return
	}
	q := r.URL.Query()
	all := q.Get("all") == "1"
	if all && s.d.Authorize(sess.id.Principal(), authz.ExportHistoryAll, true) != nil {
		s.denyCoalesced(r, sess, authz.ExportHistoryAll, "forbidden")
		s.errorPage(w, r, http.StatusForbidden, "Exporting every sensor at once needs the operator role. Export one sensor from its panel.")
		return
	}
	p, err := history.ParsePlan(q, s.d.History.Now())
	keys, kok := s.historyKeys(r.Context(), v.ID)
	key, found := keyByName(keys, q.Get("sensor"))
	switch {
	case err != nil:
		s.errorPage(w, r, http.StatusBadRequest, "The range could not be read. Pick it from the History tab.")
		return
	case !kok:
		s.errorPage(w, r, http.StatusInternalServerError, "The history could not be read. Try again.")
		return
	case !all && !found:
		s.errorPage(w, r, http.StatusBadRequest, "No history for that sensor. Pick it from the History tab.")
		return
	}
	if all {
		key = store.SensorKey{} // the file is named all-sensors
	} else {
		keys = []store.SensorKey{key}
	}
	s.streamHistory(w, r, history.Export{ServerID: v.ID, Keys: keys, Plan: p, Raw: q.Get("raw") == "1"}, key.Key)
}

func (s *server) streamHistory(w http.ResponseWriter, r *http.Request, e history.Export, sensor string) {
	prep, err := s.d.History.PrepareExport(r.Context(), e)
	switch {
	case errors.Is(err, history.ErrTooManyRows):
		s.errorPage(w, r, http.StatusRequestEntityTooLarge, "More than 100 000 rows for one export. Pick a shorter range, one sensor, or the summarized (not raw) export.")
		return
	case errors.Is(err, history.ErrRawSpan):
		s.errorPage(w, r, http.StatusBadRequest, "Raw samples can be exported for at most 31 days. Use the summarized export for longer ranges.")
		return
	case err != nil:
		s.d.Logger.Error("ui history export failed", "server", e.ServerID, "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "The history could not be read. Try again.")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/csv; charset=utf-8")
	h.Set("Content-Disposition", csvx.ContentDisposition(history.ExportName(e.ServerID, sensor, e.Plan, e.Raw, s.d.Now())))
	h.Set("Cache-Control", "no-store")
	rc := http.NewResponseController(w)
	if werr := s.d.History.WriteCSV(r.Context(), w, func() { _ = rc.Flush() }, prep); werr != nil {
		// The status and part of the file are out: abort the response, so the browser sees
		// a failed download instead of a clean end of a cut file.
		s.d.Logger.Warn("ui history export ended early; response aborted", "server", e.ServerID, "err", werr)
		panic(http.ErrAbortHandler)
	}
}

// historySize is the Settings → General line about the history's size, as of the
// janitor's last hourly pass ("" without the history).
func (s *server) historySize(sess session) string {
	if !s.historyOn() {
		return ""
	}
	st := s.d.History.Status()
	if st.LastRun.IsZero() {
		return "The history's size is measured at its first hourly pass."
	}
	return fmt.Sprintf("Database file %s: %s raw samples, %s hourly and %s daily summaries; last rollup %s.",
		fmtSize(st.Stats.DBBytes), fmtCount(st.Stats.RawRows), fmtCount(st.Stats.HourlyRows), fmtCount(st.Stats.DailyRows),
		sess.tf().short(st.LastRun, s.d.Now()))
}

// fmtSize is a byte count as "38 MB" (decimal units, like the plan's estimates).
func fmtSize(n int64) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1f GB", float64(n)/1e9)
	case n >= 1_000_000:
		return fmt.Sprintf("%.0f MB", float64(n)/1e6)
	default:
		return fmt.Sprintf("%.0f kB", float64(n)/1e3)
	}
}

// fmtCount is a row count as "1.2 M", "48 k" or "950".
func fmtCount(n int64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1f M", float64(n)/1e6)
	case n >= 10_000:
		return fmt.Sprintf("%.0f k", float64(n)/1e3)
	default:
		return fmt.Sprint(n)
	}
}

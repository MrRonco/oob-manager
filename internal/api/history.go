package api

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"time"

	"oob-manager/internal/csvx"
	"oob-manager/internal/history"
	"oob-manager/internal/store"
	"oob-manager/internal/web"
)

// HistoryView is the sensor history (history.Service, docs/tech_doc.md §39). Every read
// is served from the database's read-only connection; nothing reaches a BMC.
type HistoryView interface {
	Now() time.Time
	Sensors(ctx context.Context, serverID string) ([]store.SensorKey, error)
	Series(ctx context.Context, k store.SensorKey, p history.Plan) (history.Series, error)
	ClockJump(ctx context.Context) (time.Time, error)
	PrepareExport(ctx context.Context, e history.Export) (history.PreparedExport, error)
	WriteCSV(ctx context.Context, w io.Writer, flush func(), p history.PreparedExport) error
}

type sensorJSON struct {
	Key   string     `json:"key"`
	Kind  string     `json:"kind"`
	Name  string     `json:"name"`
	Unit  string     `json:"unit"`
	First *time.Time `json:"first"`
	Last  *time.Time `json:"last"`
}

type pointJSON struct {
	T   time.Time `json:"t"`
	Min float64   `json:"min"`
	Avg float64   `json:"avg"`
	Max float64   `json:"max"`
	N   int64     `json:"n"`
}

type seriesMeta struct {
	Sensor    string     `json:"sensor"`
	Kind      string     `json:"kind"`
	Unit      string     `json:"unit"`
	Tier      string     `json:"tier"`
	Tiers     []string   `json:"tiers"`
	StepS     int64      `json:"step_s"`
	From      time.Time  `json:"from"`
	To        time.Time  `json:"to"`
	Points    int        `json:"points"`
	ClockJump *time.Time `json:"clock_jump"`
}

// historyFor checks the service, the server and its sensors; false has answered.
func (a *API) historyFor(w http.ResponseWriter, r *http.Request) (HistoryView, []store.SensorKey, bool) {
	hv := a.deps.History
	if hv == nil {
		web.WriteProblem(w, r, http.StatusNotFound, "the sensor history is not available")
		return nil, nil, false
	}
	id := r.PathValue("id")
	if _, ok := a.deps.Fleet.Server(id); !ok {
		web.WriteProblem(w, r, http.StatusNotFound, "unknown server")
		return nil, nil, false
	}
	keys, err := hv.Sensors(r.Context(), id)
	if err != nil {
		a.deps.Logger.Error("api: history sensors failed", "err", err)
		web.WriteProblem(w, r, http.StatusInternalServerError, "the sensor history could not be read")
		return nil, nil, false
	}
	return hv, keys, true
}

func (a *API) historySensors(w http.ResponseWriter, r *http.Request) {
	_, keys, ok := a.historyFor(w, r)
	if !ok {
		return
	}
	out := make([]sensorJSON, 0, len(keys))
	for _, k := range keys {
		out = append(out, sensorJSON{Key: k.Key, Kind: string(k.Kind), Name: k.Name, Unit: string(k.Unit),
			First: timePtr(k.First), Last: timePtr(k.Last)})
	}
	writeJSON(w, http.StatusOK, list[sensorJSON]{Data: out, Meta: map[string]int{"total": len(out)}})
}

// sensorOf finds the requested sensor by its key; an unknown one answers 400.
func sensorOf(w http.ResponseWriter, r *http.Request, keys []store.SensorKey) (store.SensorKey, bool) {
	key := r.URL.Query().Get("sensor")
	if i := slices.IndexFunc(keys, func(k store.SensorKey) bool { return k.Key == key }); i >= 0 {
		return keys[i], true
	}
	web.WriteProblem(w, r, http.StatusBadRequest, "unknown sensor: list them at /api/v1/servers/{id}/history/sensors")
	return store.SensorKey{}, false
}

func planOf(w http.ResponseWriter, r *http.Request, now time.Time) (history.Plan, bool) {
	p, err := history.ParsePlan(r.URL.Query(), now)
	if err != nil {
		web.WriteProblem(w, r, http.StatusBadRequest,
			"invalid range: range=24h|7d|30d|1y, or from and to (RFC 3339, at most 2 years) with an optional step in seconds")
		return history.Plan{}, false
	}
	return p, true
}

func (a *API) historySeries(w http.ResponseWriter, r *http.Request) {
	hv, keys, ok := a.historyFor(w, r)
	if !ok {
		return
	}
	k, ok := sensorOf(w, r, keys)
	if !ok {
		return
	}
	p, ok := planOf(w, r, hv.Now())
	if !ok {
		return
	}
	sr, err := hv.Series(r.Context(), k, p)
	jump, jerr := hv.ClockJump(r.Context())
	if err = errors.Join(err, jerr); err != nil {
		a.deps.Logger.Error("api: history series failed", "err", err)
		web.WriteProblem(w, r, http.StatusInternalServerError, "the sensor history could not be read")
		return
	}
	data := make([]pointJSON, 0, len(sr.Buckets))
	for _, b := range sr.Buckets {
		data = append(data, pointJSON{T: b.Start.UTC(), Min: b.Min, Avg: b.Avg, Max: b.Max, N: b.N})
	}
	tiers := []string{}
	for _, s := range sr.Segments {
		if !slices.Contains(tiers, string(s.Tier)) {
			tiers = append(tiers, string(s.Tier))
		}
	}
	writeJSON(w, http.StatusOK, list[pointJSON]{Data: data, Meta: seriesMeta{Sensor: k.Key, Kind: string(k.Kind),
		Unit: string(k.Unit), Tier: string(p.Tier), Tiers: tiers, StepS: int64(p.Step / time.Second), From: p.From.UTC(),
		To: p.To.UTC(), Points: p.Points(), ClockJump: timePtr(jump)}})
}

// historyCSV exports one sensor (sensor=…), bucketed like the chart or raw (raw=1).
// Every sensor at once (all=1) is an operator action in a browser session: tokens
// export one sensor per request.
func (a *API) historyCSV(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Has("all") {
		web.WriteProblem(w, r, http.StatusForbidden, "exporting every sensor at once needs an operator session; export one sensor per request")
		return
	}
	hv, keys, ok := a.historyFor(w, r)
	if !ok {
		return
	}
	k, ok := sensorOf(w, r, keys)
	if !ok {
		return
	}
	p, ok := planOf(w, r, hv.Now())
	if !ok {
		return
	}
	if wait, allowed := a.exports.allow(tokenID(r.Context())); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
		web.WriteProblem(w, r, http.StatusTooManyRequests, "export rate limit exceeded")
		return
	}
	raw := r.URL.Query().Get("raw") == "1"
	prep, err := hv.PrepareExport(r.Context(), history.Export{ServerID: r.PathValue("id"), Keys: []store.SensorKey{k}, Plan: p, Raw: raw})
	if !a.exportRefused(w, r, err) {
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", csvx.ContentDisposition(history.ExportName(r.PathValue("id"), k.Key, p, raw, hv.Now())))
	w.Header().Set("Cache-Control", "no-store")
	rc := http.NewResponseController(w)
	if werr := hv.WriteCSV(r.Context(), w, func() { _ = rc.Flush() }, prep); werr != nil {
		// The status and part of the file are out: abort the response, so the client sees
		// a broken transfer instead of a clean end of a cut file.
		a.deps.Logger.Warn("api: history export ended early; response aborted", "err", werr)
		panic(http.ErrAbortHandler)
	}
}

// exportRefused answers a refused or failed export; true means go on.
func (a *API) exportRefused(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, history.ErrTooManyRows):
		web.WriteProblem(w, r, http.StatusRequestEntityTooLarge, "more than 100000 rows: pick a shorter range or a bucketed export")
	case errors.Is(err, history.ErrRawSpan):
		web.WriteProblem(w, r, http.StatusBadRequest, "a raw export covers at most 31 days")
	default:
		a.deps.Logger.Error("api: history export failed", "err", err)
		web.WriteProblem(w, r, http.StatusInternalServerError, "the sensor history could not be read")
	}
	return false
}

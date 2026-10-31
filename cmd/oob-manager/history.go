package main

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"oob-manager/internal/api"
	"oob-manager/internal/config"
	"oob-manager/internal/history"
	"oob-manager/internal/metrics"
	"oob-manager/internal/store"
	"oob-manager/internal/web/ui"
)

// The sensor history (tech_doc §39): the fleet writes each poll's samples on the
// writer connection; charts, exports and their audit markers read a separate read-only
// pool; the janitor rolls up and prunes on the writer, in short batches.

// openHistory opens the read-only pool next to the writer (which created the file,
// migrated it and switched it to WAL) and builds the service. The caller closes the pool
// after serve has stopped the janitor and every request.
func openHistory(ctx context.Context, c *core, log *slog.Logger) (*history.Service, *store.ReadDB, error) {
	ro, err := store.OpenReadOnly(ctx, c.cfg.Storage.DBPath)
	if err != nil {
		return nil, nil, err
	}
	svc, err := history.New(history.Config{Writer: c.db.History(), Reader: ro.History(), Audit: ro.AuditSearch(),
		Retention: c.historyRetention, Logger: log})
	if err != nil {
		return nil, nil, errors.Join(err, ro.Close())
	}
	return svc, ro, nil
}

// withViews returns cd with the read-side services over the runtime's fleet: the BMC
// security checks, the firmware view and the sensor history (its read-only pool open).
func withViews(ctx context.Context, cfg config.Config, c *core, rt *serverRuntime, cd consoleDeps,
	log *slog.Logger) (consoleDeps, error) {
	var err error
	if cd.security, cd.firmware, cd.catalog, err = buildViews(ctx, cfg, c, rt, cd.notify, log); err != nil {
		return cd, err
	}
	online, err := catalogOnline(c, rt.e, cd.firmware, cd.notify, cd.maint)
	if err != nil {
		return cd, err
	}
	cd.catalog.SetOnline(online)
	if cd.history, cd.historyRO, err = openHistory(ctx, c, log); err != nil {
		return cd, err
	}
	if err = rt.setHistory(ctx, cd.history); err != nil {
		return cd, errors.Join(err, cd.historyRO.Close())
	}
	return cd, nil
}

// closeHistory closes the history's read-only pool (none: nothing to do).
func (cd consoleDeps) closeHistory() {
	if cd.historyRO != nil {
		_ = cd.historyRO.Close()
	}
}

// historyRetention is the live retention (Settings → General applies at the next prune).
func (c *core) historyRetention() history.Retention {
	g := c.settings.Current().General
	return history.Retention{RawDays: g.HistoryRawDays, HourlyDays: g.HistoryHourlyDays, DailyDays: g.HistoryDailyDays}
}

// historySync is the registry hook: the history of servers that left the registry goes.
type historySync struct {
	svc atomic.Pointer[history.Service]
}

// setHistory connects the history and syncs it with the registry right away.
func (rt *serverRuntime) setHistory(ctx context.Context, svc *history.Service) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.history.svc.Store(svc)
	return rt.syncHistory(ctx)
}

// syncHistory hands every registry id (file and browser, enabled or not: a disabled
// server keeps its history) to the history, which deletes the others' rows. The caller
// holds rt.mu.
func (rt *serverRuntime) syncHistory(ctx context.Context) error {
	svc := rt.history.svc.Load()
	if svc == nil {
		return nil
	}
	entries := rt.reg.Current().Entries()
	ids := make([]string, 0, len(entries))
	for _, x := range entries {
		ids = append(ids, x.Server.ID)
	}
	return svc.SyncServers(ctx, ids)
}

// historyState adapts the janitor's status for /metrics (nil without the service).
func historyState(s *history.Service) func() metrics.HistoryState {
	if s == nil {
		return nil
	}
	return func() metrics.HistoryState {
		st := s.Status()
		return metrics.HistoryState{Ready: !st.LastRun.IsZero(), RawRows: st.Stats.RawRows, HourlyRows: st.Stats.HourlyRows,
			DailyRows: st.Stats.DailyRows, DBBytes: st.Stats.DBBytes, FreelistPages: st.Stats.FreelistPages,
			HourlyDone: st.HourlyDone, DailyDone: st.DailyDone, PruneTook: st.PruneTook}
	}
}

// uiHistory and apiHistory keep a nil service a nil interface (the history is hidden).
// now (nil in production: env.uiHistoryNow) replaces the UI's view of the clock.
func uiHistory(s *history.Service, now func() time.Time) ui.History {
	switch {
	case s == nil:
		return nil
	case now != nil:
		return frozenHistory{Service: s, now: now}
	}
	return s
}

// frozenHistory is the history with another "now" for the UI (env.uiHistoryNow).
type frozenHistory struct {
	*history.Service
	now func() time.Time
}

func (f frozenHistory) Now() time.Time { return f.now() }

func apiHistory(s *history.Service) api.HistoryView {
	if s == nil {
		return nil
	}
	return s
}

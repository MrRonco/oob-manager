package maint

import (
	"context"
	"fmt"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/notify"
	"oob-manager/internal/store"
)

// Reasons recorded when a window ends.
const (
	EndedByUser   = "ended"
	EndedExpired  = "expired"
	EndedCanceled = "cancelled" // a scheduled window removed before it began
	EndedRemoved  = "server_removed"
)

// Start opens (or schedules) a maintenance window. A server has at most one window:
// ErrExists while one is active or scheduled. A window that starts now sends the
// single "maintenance started" notification right away; a scheduled one when it begins.
func (s *Service) Start(ctx context.Context, a admin.Actor, serverID string, req StartRequest) (Window, error) {
	now := s.cfg.Now().UTC().Truncate(time.Second)
	w, verr := newWindow(serverID, req, a.Username, now)
	if verr != nil {
		return Window{}, verr
	}
	s.write.Lock()
	defer s.write.Unlock()
	if old, ok := s.st.Load().windows[serverID]; ok {
		if !old.ExpiredAt(now) {
			return Window{}, ErrExists
		}
		if err := s.expire(ctx, old, now); err != nil { // Run has not seen it yet
			return Window{}, err
		}
	}
	w.Notified = w.ActiveAt(now)
	err := s.change(ctx, func(tx *store.Tx) error {
		if err := tx.Maint().PutWindow(ctx, toRow(w)); err != nil {
			return mapStoreErr(err)
		}
		_, err := s.cfg.Audit.RecordTx(ctx, tx, entry(a, serverID, ActionStart, startParams(w, now)))
		return err
	})
	if err != nil {
		return Window{}, err
	}
	if w.Notified {
		s.emit(s.startedEvent(w, now))
	}
	return w, nil
}

func newWindow(serverID string, req StartRequest, by string, now time.Time) (Window, error) {
	reason, err := CleanReason(req.Reason)
	if err != nil {
		return Window{}, err
	}
	if serverID == "" || len(serverID) > 64 {
		return Window{}, fmt.Errorf("%w: unknown server", ErrInvalid)
	}
	if req.Duration != 0 && (req.Duration < MinWindow || req.Duration > MaxWindow) {
		return Window{}, fmt.Errorf("%w: a window lasts from %s to %s, or until it is ended", ErrInvalid, MinWindow, "7 days")
	}
	start := now
	if !req.StartsAt.IsZero() {
		start = req.StartsAt.UTC().Truncate(time.Second)
		if start.Before(now.Add(-time.Minute)) || start.After(now.Add(MaxScheduleAhead)) {
			return Window{}, fmt.Errorf("%w: the start must be between now and 30 days ahead", ErrInvalid)
		}
		start = maxTime(start, now)
	}
	w := Window{ServerID: serverID, StartsAt: start, Reason: reason, By: by, CreatedAt: now}
	if req.Duration > 0 {
		w.EndsAt = start.Add(req.Duration)
	}
	return w, nil
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func startParams(w Window, now time.Time) map[string]any {
	p := map[string]any{"reason": w.Reason, "until": "until ended"}
	if !w.EndsAt.IsZero() {
		p["until"], p["minutes"] = w.EndsAt.Format(time.RFC3339), int(w.EndsAt.Sub(w.StartsAt)/time.Minute)
	}
	if w.StartsAt.After(now) {
		p["starts"] = w.StartsAt.Format(time.RFC3339)
	}
	return p
}

func toRow(w Window) store.MaintenanceRow {
	return store.MaintenanceRow{ServerID: w.ServerID, StartsAt: w.StartsAt, EndsAt: w.EndsAt, Reason: w.Reason,
		CreatedBy: w.By, CreatedAt: w.CreatedAt, StartedNotified: w.Notified}
}

// End ends a server's window now (or cancels a scheduled one). ErrNotFound when there is
// none. A window that had started sends "maintenance ended".
func (s *Service) End(ctx context.Context, a admin.Actor, serverID string) error {
	s.write.Lock()
	defer s.write.Unlock()
	w, ok := s.st.Load().windows[serverID]
	if !ok {
		return ErrNotFound
	}
	reason := EndedByUser
	if w.ScheduledAt(s.cfg.Now()) {
		reason = EndedCanceled
	}
	if err := s.remove(ctx, a, w, reason); err != nil {
		return err
	}
	if w.Notified {
		s.emit(notify.MaintenanceEvent(notify.MaintenanceChange{ServerID: serverID, ServerName: s.name(serverID),
			By: a.Username}, s.cfg.Now()))
	}
	return nil
}

func (s *Service) remove(ctx context.Context, a admin.Actor, w Window, reason string) error {
	return s.change(ctx, func(tx *store.Tx) error {
		if err := tx.Maint().DeleteWindow(ctx, w.ServerID); err != nil {
			return mapStoreErr(err)
		}
		_, err := s.cfg.Audit.RecordTx(ctx, tx, entry(a, w.ServerID, ActionEnd, map[string]any{"reason": reason,
			"window_reason": w.Reason}))
		return err
	})
}

func (s *Service) startedEvent(w Window, now time.Time) notify.Event {
	return notify.MaintenanceEvent(notify.MaintenanceChange{ServerID: w.ServerID, ServerName: s.name(w.ServerID),
		Started: true, Until: w.EndsAt, Reason: w.Reason, By: w.By}, now)
}

// Run sends the notifications of scheduled windows as they begin and ends expired
// windows (audited as system, "maintenance ended" sent), every Config.Every until ctx
// ends. Acknowledgements older than AckRetention are pruned once a day.
func (s *Service) Run(ctx context.Context) {
	tick := time.NewTicker(s.cfg.Every)
	defer tick.Stop()
	var pruned time.Time
	for {
		s.Tick(ctx)
		if now := s.cfg.Now(); now.Sub(pruned) >= 24*time.Hour {
			s.prune(ctx, now)
			pruned = now
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Tick handles every window that began or expired since the last call.
func (s *Service) Tick(ctx context.Context) {
	if s.cfg.DB == nil {
		return
	}
	s.write.Lock()
	defer s.write.Unlock()
	now := s.cfg.Now()
	for _, w := range s.st.Load().windows {
		var err error
		switch {
		case w.ExpiredAt(now):
			err = s.expire(ctx, w, now)
		case w.ActiveAt(now) && !w.Notified:
			err = s.begin(ctx, w, now)
		case w.ReminderDueAt(now):
			err = s.remind(ctx, w, now)
		}
		if err != nil {
			s.cfg.Logger.Error("maint: window update failed", "server", w.ServerID, "err", err)
		}
	}
}

func (s *Service) expire(ctx context.Context, w Window, now time.Time) error {
	if err := s.remove(ctx, systemActor, w, EndedExpired); err != nil {
		return err
	}
	if w.Notified {
		s.emit(notify.MaintenanceEvent(notify.MaintenanceChange{ServerID: w.ServerID, ServerName: s.name(w.ServerID),
			By: "system", Expired: true}, now))
	}
	return nil
}

func (s *Service) begin(ctx context.Context, w Window, now time.Time) error {
	if err := s.cfg.DB.Maint().MarkStarted(ctx, w.ServerID); err != nil {
		return err
	}
	if err := s.reload(ctx); err != nil {
		return err
	}
	s.emit(s.startedEvent(w, now))
	return nil
}

// remind sends the daily "still in maintenance" message of an open-ended window and
// records it, so a restart neither repeats nor skips one. A day the app was down is not
// made up: one reminder on return, then one per OpenEndedAfter. Not audited (nothing
// changed; the notification itself is the record).
func (s *Service) remind(ctx context.Context, w Window, now time.Time) error {
	if err := s.cfg.DB.Maint().MarkReminded(ctx, w.ServerID, now); err != nil {
		return err
	}
	if err := s.reload(ctx); err != nil {
		return err
	}
	s.emit(notify.MaintenanceEvent(notify.MaintenanceChange{ServerID: w.ServerID, ServerName: s.name(w.ServerID),
		Reminder: true, Since: w.StartsAt, Reason: w.Reason, By: w.By}, now))
	return nil
}

func (s *Service) prune(ctx context.Context, now time.Time) {
	if s.cfg.DB == nil {
		return
	}
	n, err := s.cfg.DB.Maint().PruneAcks(ctx, now.Add(-AckRetention))
	if err != nil {
		s.cfg.Logger.Error("maint: pruning acknowledgements failed", "err", err)
		return
	}
	if n > 0 {
		s.cfg.Logger.Info("maint: old acknowledgements pruned", "count", n)
		if err := s.reload(ctx); err != nil {
			s.cfg.Logger.Error("maint: reload failed", "err", err)
		}
	}
}

// SyncServers is told every server id in the registry (config.yaml and browser, enabled
// or not) after each change. The window of a server that no longer exists is removed in
// one transaction with its audit row (server.maintenance.end by system, reason
// server_removed), so a server re-created with the same id is not silently in
// maintenance. Notes and acknowledgements are kept (they suppress nothing).
func (s *Service) SyncServers(ctx context.Context, ids []string) error {
	if s.cfg.DB == nil {
		return nil
	}
	known := make(map[string]bool, len(ids))
	for _, id := range ids {
		known[id] = true
	}
	s.write.Lock()
	defer s.write.Unlock()
	var stale []Window
	for id, w := range s.st.Load().windows {
		if !known[id] {
			stale = append(stale, w)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	err := s.change(ctx, func(tx *store.Tx) error {
		for _, w := range stale {
			if err := tx.Maint().DeleteWindow(ctx, w.ServerID); err != nil {
				return err
			}
			e := entry(systemActor, w.ServerID, ActionEnd, map[string]any{"reason": EndedRemoved})
			if _, err := s.cfg.Audit.RecordTx(ctx, tx, e); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		s.cfg.Logger.Info("maint: removed the windows of deleted servers", "count", len(stale))
	}
	return err
}

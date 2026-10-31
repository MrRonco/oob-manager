package bmcreset

import (
	"context"
	"errors"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/fleet"
	"oob-manager/internal/store"
)

// Error classes of a window that did not end with the BMC back.
const (
	classTimeout       = "timeout"
	classConfigChanged = "config_changed"
	classTLS           = "tls"
	// classUnobserved: the app was not running when the deadline passed, so nobody saw
	// whether the BMC came back in time.
	classUnobserved = "unobserved"
)

// onEnd is the fleet's window callback: it runs on the poller's goroutine (or inside
// Apply) and must not block, so the work happens in the background.
func (s *Service) onEnd(id string, requestedAt time.Time, e fleet.RestartEnd) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.open[id]
	if s.closed || !ok || !o.rq.at.Equal(requestedAt) {
		return // after Shutdown the row stays open: the next start re-arms it
	}
	delete(s.open, id)
	s.wg.Go(func() { s.finish(o, e) })
}

// finish closes the row, audits the outcome and runs AfterBack or AfterTimeout.
func (s *Service) finish(o openReset, e fleet.RestartEnd) {
	rec := Record{RequestedAt: o.rq.at, SentAt: o.sentAt, By: o.rq.actor.Username, Deadline: o.until, BackAt: e.At}
	params := map[string]any{}
	if o.rearmed {
		params["rearmed"] = true // the app was down for part of the window
	}
	var result string
	switch e.Outcome {
	case fleet.RestartBack:
		result, rec.Result, rec.Detail = audit.ResultOK, store.BMCResetVerified, verifiedDetail(o, e, params)
	default:
		rec.Result, rec.BackAt, rec.Class = store.BMCResetTimeout, time.Time{}, endClass(e)
		result = audit.ResultError
	}
	s.finishRow(o.rowID, rec.Result, rec.BackAt, rec.Class, rec.Detail)
	if rec.Result == store.BMCResetVerified {
		params["restart_confirmed"] = rec.Detail == ""
	}
	s.mu.Lock()
	s.last[o.rq.id] = rec
	if rec.Result == store.BMCResetVerified && rec.Detail == "" {
		s.verified[o.rq.id] = rec
	}
	s.count(o.rq.id, rec.Result)
	s.mu.Unlock()
	sys := request{id: o.rq.id, actor: Actor{Username: systemActor, AuthMethod: systemActor}, corr: o.rq.corr}
	s.auditFinal(sys, ActionVerified, result, rec.Class, params)
	switch {
	case rec.Result == store.BMCResetVerified && s.cfg.AfterBack != nil:
		ctx, cancel := context.WithTimeout(s.stopCtx, afterBackTimeout)
		defer cancel()
		s.cfg.AfterBack(ctx, o.rq.id)
	case e.Outcome == fleet.RestartTimeout && s.cfg.AfterTimeout != nil:
		s.cfg.AfterTimeout(o.rq.id)
	}
}

// verifiedDetail fills the verified row's audit params and returns its detail. The
// downtime counts from the POST. An iDRAC9 reports LastResetTime, which must not be
// older than the POST (one second of slack: the BMC reports whole seconds); it is judged
// only on capabilities probed at or after the POST (review C-M4), else the check is
// recorded as not done. A POST that got no answer is confirmed only by a newer
// LastResetTime; otherwise the row says restart_unconfirmed (review C-M2).
func verifiedDetail(o openReset, e fleet.RestartEnd, params map[string]any) string {
	params["downtime_s"] = int64(e.At.Sub(o.sentAt) / time.Second)
	if o.unconfirmed {
		params["post_unconfirmed"] = true
	}
	f := e.State.Capabilities.Flags()
	if e.State.HasCapabilities && f.BMCFirmware != "" {
		params["firmware_version"] = f.BMCFirmware
	}
	switch {
	case !e.State.HasCapabilities || f.BMCLastReset.IsZero():
		params["last_reset_time_check"] = "not_reported"
	case f.ProbedAt.Before(o.sentAt):
		params["last_reset_time_check"] = "not_done" // the probe after the return did not run
	case f.BMCLastReset.Before(o.sentAt.Truncate(time.Second)):
		params["last_reset_time_unchanged"] = true
		return store.BMCResetUnchanged
	default:
		params["last_reset_time"] = f.BMCLastReset.UTC().Format(time.RFC3339)
		return ""
	}
	if o.unconfirmed {
		return store.BMCResetUnconfirmed
	}
	return ""
}

func endClass(e fleet.RestartEnd) string {
	switch {
	case e.Outcome == fleet.RestartConfigChanged:
		return classConfigChanged
	case e.State.PinMismatch:
		return classTLS
	default:
		return classTimeout
	}
}

// finishRow closes a row, retrying a failed write; a row that is no longer open keeps
// its first outcome.
func (s *Service) finishRow(rowID int64, result string, backAt time.Time, class, detail string) {
	err := retry(func() error {
		err := s.cfg.Store.Finish(context.Background(), rowID, result, backAt, class, detail)
		if errors.Is(err, store.ErrConflict) {
			return nil
		}
		return err
	})
	if err != nil {
		s.cfg.Logger.Error("bmc reset: closing the row failed", "row", rowID, "err", err)
	}
}

// Start loads the history (cooldowns, the panels' last resets) and re-arms the window
// of every reset whose deadline has not passed, so an app restart during a BMC restart
// raises no alarm. A row whose deadline passed while the app was down is closed as a
// timeout (class unobserved). Call it once, after the fleet has its servers.
func (s *Service) Start(ctx context.Context) error {
	latest, err := s.cfg.Store.Latest(ctx)
	if err != nil {
		return err
	}
	verified, err := s.cfg.Store.LastVerified(ctx)
	if err != nil {
		return err
	}
	open, err := s.cfg.Store.Open(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	for _, r := range latest {
		s.next[r.ServerID] = r.RequestedAt.Add(s.cfg.Cooldown)
		s.last[r.ServerID] = recordOf(r)
	}
	for _, r := range verified {
		s.verified[r.ServerID] = recordOf(r)
	}
	s.mu.Unlock()
	for _, r := range open {
		s.rearm(r)
	}
	return nil
}

// rearm re-opens the window of an open row, or closes the row when that cannot be done.
func (s *Service) rearm(r store.BMCResetRow) {
	rq := request{id: r.ServerID, actor: Actor{Username: r.RequestedBy}, corr: r.CorrelationID, at: r.RequestedAt}
	o := openReset{rowID: r.ID, rq: rq, sentAt: r.SentAt, until: r.DeadlineAt, unconfirmed: r.Unconfirmed, rearmed: true}
	if !s.cfg.Now().Before(r.DeadlineAt) {
		s.closeUnwatched(o, classUnobserved)
		return
	}
	w := fleet.RestartWindow{Since: r.SentAt, Until: r.DeadlineAt, By: r.RequestedBy}
	s.mu.Lock()
	err := s.cfg.Fleet.ExpectRestart(r.ServerID, w, func(e fleet.RestartEnd) { s.onEnd(rq.id, rq.at, e) })
	if err == nil {
		s.open[r.ServerID] = o
	}
	s.mu.Unlock()
	if err != nil {
		s.closeUnwatched(o, classOf(err))
	}
}

// closeUnwatched closes a row the app could not watch and audits it as a timeout.
func (s *Service) closeUnwatched(o openReset, class string) {
	if class != classUnobserved && class != classTLS {
		class = classConfigChanged
	}
	s.finishRow(o.rowID, store.BMCResetTimeout, time.Time{}, class, "")
	s.mu.Lock()
	s.last[o.rq.id] = Record{RequestedAt: o.rq.at, SentAt: o.sentAt, By: o.rq.actor.Username, Result: store.BMCResetTimeout,
		Deadline: o.until, Class: class}
	s.mu.Unlock()
	sys := request{id: o.rq.id, actor: Actor{Username: systemActor, AuthMethod: systemActor}, corr: o.rq.corr}
	s.auditFinal(sys, ActionVerified, audit.ResultError, class, nil)
}

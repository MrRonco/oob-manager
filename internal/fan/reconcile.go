package fan

import (
	"context"
	"errors"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/bmc"
	"oob-manager/internal/store"
)

// Run reconciles once in startup mode (unexpired leases are applied again, leftovers
// swept), then every Tick until ctx ends. Leases outlive the process on purpose: the
// enforcing side (host script, BMC) keeps them, and the next start reconciles.
func (s *Service) Run(ctx context.Context) {
	s.Reconcile(ctx, true)
	t := time.NewTicker(s.cfg.Tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Reconcile(ctx, false)
		}
	}
}

// Reconcile walks every active lease: past expiry → release and mark expired; pending
// and confirmed by the enforcing side → applied; at startup an unexpired lease is applied
// again (idempotent), so a crash between "stored" and "applied" heals itself. A lease
// for a server that no longer has fan control is closed. Failures are logged and
// retried on the next pass.
func (s *Service) Reconcile(ctx context.Context, startup bool) {
	leases, err := s.cfg.Leases.ListByStates(ctx, store.LeasePending, store.LeaseApplied)
	if err != nil {
		s.cfg.Logger.Error("fan reconcile: list leases", "err", err)
		return
	}
	active := map[string]bool{}
	for _, l := range leases {
		if s.reconcileOne(ctx, l, startup) {
			active[l.ServerID] = true
		}
	}
	if startup {
		s.sweep(ctx, active)
	}
	s.reapplyPending(ctx)
}

// reconcileOne reports whether the lease is still active afterwards.
func (s *Service) reconcileOne(ctx context.Context, l store.FanLease, startup bool) bool {
	_, ap, mu, err := s.target(l.ServerID)
	if err != nil {
		s.closeOrphan(ctx, l)
		return false
	}
	mu.Lock()
	defer mu.Unlock()
	if !s.current(l.ServerID, mu) {
		return true // the setup changed meanwhile; SetTargets handled this lease
	}
	cur, err := s.cfg.Leases.Get(ctx, l.LeaseID)
	if err != nil || !cur.State.Active() {
		return false // ended meanwhile
	}
	switch {
	case !s.cfg.Now().Before(cur.ExpiresAt):
		return !s.expire(ctx, ap, cur)
	case startup:
		s.reapply(ctx, ap, cur)
	case cur.State == store.LeasePending:
		s.confirm(ctx, ap, cur)
	}
	return true
}

// expire reports whether the lease was released and closed.
func (s *Service) expire(ctx context.Context, ap Applier, l store.FanLease) bool {
	params := map[string]any{"lease_id": l.LeaseID, "pct": l.Pct}
	if l.HasOriginal {
		params["restored"] = l.OriginalValue
	}
	if err := ap.Release(ctx, l); err != nil {
		s.cfg.Logger.Error("fan lease expiry: release failed, retrying", "server", l.ServerID, "lease", l.LeaseID, "err", err)
		return false
	}
	if err := s.cfg.Leases.Transition(ctx, l.LeaseID, l.State, store.LeaseExpired, s.cfg.Now()); err != nil {
		s.cfg.Logger.Error("fan lease expiry: state", "server", l.ServerID, "err", err)
		return false
	}
	s.system(ctx, ActionExpire, l.ServerID, audit.ResultOK, "", params)
	return true
}

func (s *Service) reapply(ctx context.Context, ap Applier, l store.FanLease) {
	immediate, err := ap.Apply(ctx, l)
	params := map[string]any{"lease_id": l.LeaseID, "pct": l.Pct}
	if err != nil {
		s.cfg.Logger.Error("fan lease re-apply at startup failed", "server", l.ServerID, "err", err)
		s.system(ctx, ActionReapply, l.ServerID, audit.ResultError, errorClass(err), params)
		return
	}
	if immediate && l.State == store.LeasePending {
		_ = s.cfg.Leases.Transition(ctx, l.LeaseID, store.LeasePending, store.LeaseApplied, s.cfg.Now())
	}
	s.system(ctx, ActionReapply, l.ServerID, audit.ResultOK, "", params)
}

func (s *Service) confirm(ctx context.Context, ap Applier, l store.FanLease) {
	obs := ap.Observe(l, true)
	if !obs.Applied {
		return
	}
	if err := s.cfg.Leases.Transition(ctx, l.LeaseID, store.LeasePending, store.LeaseApplied, s.cfg.Now()); err != nil {
		s.cfg.Logger.Error("fan lease applied: state", "server", l.ServerID, "err", err)
		return
	}
	s.system(ctx, ActionApplied, l.ServerID, audit.ResultOK, "",
		map[string]any{"lease_id": l.LeaseID, "pct": l.Pct, "applied_pct": obs.AppliedPct})
}

// closeOrphan ends a lease whose server lost fan control in config. Nothing can be
// released through an applier that no longer exists; the lease file (hostlease) still
// carries its own expiry, and a BMC floor errs on the side of more cooling.
func (s *Service) closeOrphan(ctx context.Context, l store.FanLease) {
	if err := s.cfg.Leases.Transition(ctx, l.LeaseID, l.State, store.LeaseExpired, s.cfg.Now()); err != nil {
		s.cfg.Logger.Error("fan reconcile: close orphan lease", "server", l.ServerID, "err", err)
		return
	}
	s.cfg.Logger.Warn("fan lease closed: server has no fan control configured", "server", l.ServerID)
	s.system(ctx, ActionExpire, l.ServerID, audit.ResultError, "not_configured", map[string]any{"lease_id": l.LeaseID})
}

func (s *Service) sweep(ctx context.Context, active map[string]bool) {
	for id, ap := range s.cur.Load().appliers {
		sw, ok := ap.(Sweeper)
		if !ok || active[id] {
			continue
		}
		if err := sw.Sweep(ctx); err != nil {
			s.cfg.Logger.Error("fan sweep failed", "server", id, "err", err)
		}
	}
}

func (s *Service) system(ctx context.Context, action, serverID, result, class string, params map[string]any) {
	_ = s.audit(ctx, audit.Entry{Principal: systemActor, AuthMethod: systemActor, ServerID: serverID,
		Action: action, Params: params, Result: result, ErrorClass: class})
}

// errorClass is the coarse class stored in audit rows; never the error text.
func errorClass(err error) string {
	if c := bmc.Classify(err); c != bmc.ClassOther && c != bmc.ClassNone {
		return string(c)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return string(bmc.ClassTimeout)
	}
	return "apply"
}

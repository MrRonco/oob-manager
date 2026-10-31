package fan

import (
	"context"
	"errors"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/config"
	"oob-manager/internal/store"
)

// Re-apply backoff for a floor whose BMC is not back yet: one attempt after
// reapplyFirstWait, doubling to reapplyMaxWait, so a dead BMC is not logged in to every
// reconciler tick.
const (
	reapplyFirstWait = time.Minute
	reapplyMaxWait   = 15 * time.Minute
)

type reapplyState struct {
	next time.Time
	wait time.Duration
}

// ReapplyAfterBMCReset applies server serverID's active, unexpired lease again after
// its BMC restarted (tech_doc §37), for the modes whose effect lives on the BMC
// (redfish-floor: an iDRAC attribute, expected but not verified to survive a graceful
// restart). Apply is idempotent, so this is safe whether or not the value reverted. A
// host-lease is untouched: its lease file is on the host. It reports whether a lease
// was applied again; the attempt is audited as fan.lease.reapply with reason bmc_reset.
func (s *Service) ReapplyAfterBMCReset(ctx context.Context, serverID string) (bool, error) {
	return s.reapplyFloor(ctx, serverID, true)
}

// RequestReapply asks the reconciler to apply serverID's BMC-side floor again once the
// BMC answers (review C-M3): after a restart that timed out, or after a return whose
// re-apply kept failing. Attempts back off from one minute to 15; only the success is
// audited. A server without a redfish-floor policy is ignored.
func (s *Service) RequestReapply(serverID string) {
	if p, ok := s.Policy(serverID); !ok || p.Mode != config.FanRedfishFloor {
		return
	}
	s.reMu.Lock()
	defer s.reMu.Unlock()
	s.pending[serverID] = reapplyState{next: s.cfg.Now(), wait: reapplyFirstWait}
}

// reapplyPending tries the due pending re-applies (Reconcile).
func (s *Service) reapplyPending(ctx context.Context) {
	now := s.cfg.Now()
	s.reMu.Lock()
	var due []string
	for id, st := range s.pending {
		if !now.Before(st.next) {
			due = append(due, id)
		}
	}
	s.reMu.Unlock()
	for _, id := range due {
		_, err := s.reapplyFloor(ctx, id, false)
		s.reMu.Lock()
		if st, ok := s.pending[id]; ok && err != nil {
			s.pending[id] = reapplyState{next: now.Add(st.wait), wait: min(2*st.wait, reapplyMaxWait)}
		} else {
			delete(s.pending, id) // done, or nothing left to apply
		}
		s.reMu.Unlock()
	}
}

// reapplyFloor applies the active redfish-floor lease of serverID again. A failure is
// audited only when auditFailure is set (the reconciler retries quietly).
func (s *Service) reapplyFloor(ctx context.Context, serverID string, auditFailure bool) (bool, error) {
	p, ap, mu, err := s.target(serverID)
	if err != nil || p.Mode != config.FanRedfishFloor {
		return false, nil
	}
	mu.Lock()
	defer mu.Unlock()
	if !s.current(serverID, mu) {
		return false, nil
	}
	l, err := s.cfg.Leases.Active(ctx, serverID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	case err != nil:
		return false, err
	case !s.cfg.Now().Before(l.ExpiresAt):
		return false, nil // the reconciler restores and closes it
	}
	params := map[string]any{"lease_id": l.LeaseID, "pct": l.Pct, "reason": "bmc_reset"}
	if _, err := ap.Apply(ctx, l); err != nil {
		if auditFailure {
			s.cfg.Logger.Warn("fan floor not applied again after the BMC restart", "server", serverID, "class", errorClass(err))
			s.system(ctx, ActionReapply, serverID, audit.ResultError, errorClass(err), params)
		}
		return false, err
	}
	s.system(ctx, ActionReapply, serverID, audit.ResultOK, "", params)
	return true, nil
}

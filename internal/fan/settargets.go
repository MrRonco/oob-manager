package fan

import (
	"context"
	"errors"
	"sync"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/store"
)

// reasonConfigChanged is the audit reason of a lease ended because its server's setup
// changed or the server was removed (settings slice S3).
const reasonConfigChanged = "config_changed"

// Target is one server's fan setup for SetTargets. Fingerprint identifies the applier's
// configuration (mode, address, credentials…); an unchanged fingerprint and policy keep
// the running applier.
type Target struct {
	Policy      Policy
	Applier     Applier // nil when the policy is not enabled
	Fingerprint string
}

// SetTargets replaces the fan setup (settings slice S3). Leases are restored first: a
// server whose policy or fingerprint changed, or that was removed, has its active
// lease released through its OLD applier (fans back to the enforcing side's own curve)
// and closed before the new setup is published; audited as fan.lease.end by system
// with reason config_changed. A failed release still closes the lease (a host lease
// file expires on its own; a BMC floor errs on the side of more cooling) and is audited
// as an error. Unchanged servers keep their applier, mutex and lease.
func (s *Service) SetTargets(ctx context.Context, ts []Target) error {
	next, err := buildTable(ts)
	if err != nil {
		return err
	}
	s.setMu.Lock()
	defer s.setMu.Unlock()
	old := s.cur.Load()
	var held []*sync.Mutex
	defer func() {
		for _, mu := range held {
			mu.Unlock()
		}
	}()
	for id, op := range old.policies {
		np, ok := next.policies[id]
		if ok && np == op && next.fps[id] != "" && next.fps[id] == old.fps[id] {
			next.locks[id], next.appliers[id] = old.locks[id], old.appliers[id]
			continue
		}
		mu := old.locks[id]
		mu.Lock()
		held = append(held, mu)
		if op.Enabled() {
			s.retireLease(ctx, id, old.appliers[id])
		}
	}
	s.cur.Store(next)
	return nil
}

// retireLease releases and closes id's active lease, if any. The caller holds id's mutex.
func (s *Service) retireLease(ctx context.Context, id string, ap Applier) {
	l, err := s.cfg.Leases.Active(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return
	}
	if err != nil {
		s.cfg.Logger.Error("fan: read the lease of a changed server", "server", id, "err", err)
		return
	}
	params := map[string]any{"lease_id": l.LeaseID, "pct": l.Pct, "reason": reasonConfigChanged}
	if rerr := ap.Release(ctx, l); rerr != nil {
		s.cfg.Logger.Error("fan: release on a config change failed; lease closed anyway", "server", id, "err", rerr)
		if terr := s.cfg.Leases.Transition(ctx, l.LeaseID, l.State, store.LeaseExpired, s.cfg.Now()); terr != nil {
			s.cfg.Logger.Error("fan: close lease", "server", id, "err", terr)
		}
		s.system(ctx, string(authz.FanLeaseEnd), id, audit.ResultError, errorClass(rerr), params)
		return
	}
	if terr := s.cfg.Leases.Transition(ctx, l.LeaseID, l.State, store.LeaseEnded, s.cfg.Now()); terr != nil {
		s.cfg.Logger.Error("fan: close lease", "server", id, "err", terr)
		return
	}
	s.system(ctx, string(authz.FanLeaseEnd), id, audit.ResultOK, "", params)
}

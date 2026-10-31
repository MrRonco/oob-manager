package integrations

import (
	"context"

	"oob-manager/internal/audit"
	"oob-manager/internal/config"
)

// TrustChange is what the shipper's certificate check reports (Config.OnTrust).
type TrustChange int

// Trust changes.
const (
	// TrustMismatch: the certificate does not match the pin (an impostor, or a renewed
	// certificate under a leaf pin); shipping is paused.
	TrustMismatch TrustChange = iota
	// TrustExpired: under an issuer pin, the right CA and name but an expired
	// certificate; shipping is paused until the log server renews it.
	TrustExpired
	// TrustResolved: the current destination passes the pin again.
	TrustResolved
	// TrustWithdrawn: the alert is closed because shipping was disabled or moved.
	TrustWithdrawn
)

// stop cancels r (it flushes, then closes) and tracks it until it has returned; then its
// final counters are folded into the totals.
func (s *Service) stop(r *running) {
	if r.cancel == nil { // never started; the caller holds mu, fold takes it
		s.stopped.Go(func() { s.fold(r.sh) })
		return
	}
	snap := r.sh.Stats()
	r.cancel()
	s.stopped.Go(func() {
		<-r.done
		final := r.sh.Stats()
		s.fold(r.sh)
		if final.Dropped > snap.Dropped {
			s.cfg.Logger.Warn("gelf: rows queued for the previous destination were dropped", "rows", final.Dropped-snap.Dropped)
		}
	})
}

func (s *Service) trust(c TrustChange) {
	if s.cfg.OnTrust != nil {
		s.cfg.OnTrust(c)
	}
}

// pinMismatch reports a mismatch or an expiry of the current shipper (the shipper calls
// it once per episode, so a new target that also fails is reported again).
func (s *Service) pinMismatch(gen uint64, class string) {
	if s.gen.Load() != gen {
		return
	}
	s.trustOpen.Store(true)
	if class == audit.ClassTLSExpired {
		s.trust(TrustExpired)
		return
	}
	s.trust(TrustMismatch)
}

// connected resolves an open alert once the current shipper passes the pin (also a new
// shipper after a pin confirmed for the same destination).
func (s *Service) connected(gen uint64) {
	if s.gen.Load() == gen && s.trustOpen.Swap(false) {
		s.trust(TrustResolved)
	}
}

func (s *Service) recordApplied(ctx context.Context, g config.GELF, prev *previous, err error) {
	p := map[string]any{"enabled": g.Enabled, "address": g.Address, "transport": g.Transport}
	if prev != nil {
		p["previous_confirmed"], p["queued_on_previous"] = prev.confirmed, prev.queued
	}
	e := audit.Entry{Principal: "system", AuthMethod: "system", Action: ActionApplied, Result: audit.ResultOK, Params: p}
	if err != nil {
		e.Result, e.ErrorClass = audit.ResultError, "build"
		s.cfg.Logger.Error("gelf: the new target could not be applied; the previous one keeps running", "err", err)
	}
	if _, rerr := s.cfg.Audit.Record(ctx, e); rerr != nil {
		s.cfg.Logger.Error("gelf: audit record failed", "action", ActionApplied, "err", rerr)
	}
}

// Note explains saved GELF settings that are not in force (they no longer validate);
// "" when every saved value applies.
func (s *Service) Note() string { return s.cfg.Settings.Current().IntegrationsNote }

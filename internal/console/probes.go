package console

import (
	"context"
	"time"
)

const probeTick = time.Minute

func (s *Service) recordProbe(serverID string, p Probe) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probes[serverID] = p
}

// Run probes each target's RFB banner at startup and then on the slow tier (every
// ProbeEvery; failures retried after ProbeRetry) until ctx ends. A server with an
// active console is not probed (the BMC allows one VNC session).
func (s *Service) Run(ctx context.Context) {
	s.ProbeDue(ctx)
	t := time.NewTicker(probeTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.ProbeDue(ctx)
		}
	}
}

// ProbeDue probes every target whose cached result is missing or old.
func (s *Service) ProbeDue(ctx context.Context) {
	for id, t := range *s.targets.Load() {
		if ctx.Err() != nil {
			return
		}
		if _, busy := s.broker.active(id); busy || !s.probeDue(id) {
			continue
		}
		s.recordProbe(id, probeBanner(ctx, s.cfg.Dial, t, s.cfg.Now()))
	}
}

func (s *Service) probeDue(id string) bool {
	s.mu.Lock()
	p, ok := s.probes[id]
	s.mu.Unlock()
	if !ok || p.CheckedAt.IsZero() {
		return true
	}
	age := s.cfg.Now().Sub(p.CheckedAt)
	if p.State == ProbeOK {
		return age >= s.cfg.ProbeEvery
	}
	return age >= s.cfg.ProbeRetry
}

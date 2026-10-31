package power

import (
	"context"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/bmc"
)

// startVerify records the pending operation and watches the power state in the
// background until the expected state, the timeout, a newer request or Shutdown. The
// goroutine owns ctl and closes it.
func (s *Service) startVerify(rq request, ctl Controller) {
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancels[rq.id] = cancel
	s.last[rq.id] = Operation{Action: rq.action, By: rq.actor.Username, RequestedAt: rq.at, Phase: PhasePending}
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer cancel()
		v := s.watch(ctx, rq.id, rq.action, ctl)
		_ = ctl.Close(context.Background()) // log out before the result is published
		s.finish(rq, v)
	}()
}

// verdict is the outcome of a verification.
type verdict struct {
	phase Phase
	state bmc.PowerState
	class string
}

// watch polls until the action's end state is observed or the time is up.
func (s *Service) watch(ctx context.Context, id string, a Action, ctl Controller) verdict {
	limit := s.cfg.ForcedTimeout
	if a == GracefulShutdown || a == GracefulRestart {
		limit = s.cfg.GracefulTimeout
	}
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	// The first read is immediate: a fast restart may be visible only right after the
	// reset (Off for a moment, then On again before the next poll).
	tick := time.NewTimer(0)
	defer tick.Stop()
	last, seenDown := bmc.PowerUnknown, false
	for {
		select {
		case <-ctx.Done():
			return verdict{phase: PhaseFailed, state: last, class: s.stopClass(id)}
		case <-deadline.C:
			return timedOut(a, last, seenDown)
		case <-tick.C:
			tick.Reset(s.cfg.PollEvery)
		}
		st, err := ctl.PowerState(ctx)
		if err != nil {
			continue // a busy BMC; keep trying until the deadline
		}
		last = st
		seenDown = seenDown || st != bmc.PowerOn
		if reached(a, st, seenDown) {
			return verdict{phase: PhaseDone, state: st}
		}
	}
}

// timedOut: a restart that never left On may simply have been faster than the polls
// (iDRAC often reports On throughout a reset), so it is "unconfirmed", not failed.
func timedOut(a Action, last bmc.PowerState, seenDown bool) verdict {
	if a.Restarts() && !seenDown && last == bmc.PowerOn {
		return verdict{phase: PhaseUnconfirmed, state: last}
	}
	return verdict{phase: PhaseFailed, state: last, class: "not_confirmed"}
}

// stopClass tells a superseded verification from one ended by Shutdown or by the
// server's removal (SetTargets).
func (s *Service) stopClass(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closed:
		return "stopped"
	case s.retired[id]:
		delete(s.retired, id)
		return "config_changed"
	default:
		return "superseded"
	}
}

// finish reports a verified end state to OnVerified, then stores the final operation
// (unless a newer one replaced it) and audits it. OnVerified runs first, so a reader that
// sees the final operation also sees the fleet's published state.
func (s *Service) finish(rq request, v verdict) {
	at := s.cfg.Now()
	if v.phase == PhaseDone && s.cfg.OnVerified != nil {
		s.cfg.OnVerified(rq.id, Observation{State: v.state, At: at, Action: rq.action, By: rq.actor.Username})
	}
	s.mu.Lock()
	if cur, ok := s.last[rq.id]; ok && cur.RequestedAt.Equal(rq.at) && cur.Phase == PhasePending {
		s.last[rq.id] = Operation{Action: rq.action, By: rq.actor.Username, RequestedAt: rq.at,
			FinishedAt: at, Phase: v.phase, State: v.state, Class: v.class}
		delete(s.cancels, rq.id)
	}
	s.mu.Unlock()
	params := map[string]any{"power_state": string(v.state)}
	result := audit.ResultError
	switch v.phase {
	case PhaseDone:
		result, params["outcome"] = audit.ResultOK, "verified"
	case PhaseUnconfirmed:
		result, params["outcome"] = audit.ResultOK, "unconfirmed"
	}
	_ = s.audit(rq, result, v.class, params)
}

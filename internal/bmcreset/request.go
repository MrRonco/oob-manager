package bmcreset

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
	"oob-manager/internal/store"
)

// Errors returned by Request. The UI maps each to a status and a sentence; BMC error
// text is never shown (only its class).
var (
	ErrNotConfigured = errors.New("bmcreset: server not configured")
	ErrNoOperator    = errors.New("bmcreset: needs an operator BMC account")
	ErrUnsupported   = errors.New("bmcreset: not offered by this BMC")
	ErrPowerPending  = errors.New("bmcreset: a power action is still being verified")
	ErrRestarting    = errors.New("bmcreset: the BMC is restarting")
	ErrCoolingDown   = errors.New("bmcreset: cooling down")
	ErrAudit         = errors.New("bmcreset: audit record failed; nothing was sent")
	ErrPrivilege     = errors.New("bmcreset: the operator account lacks the privilege")
	ErrBMC           = errors.New("bmcreset: the BMC did not carry out the request")
)

// CooldownError says how long to wait before the next reset of the server.
type CooldownError struct{ Left time.Duration }

func (e *CooldownError) Error() string { return fmt.Sprintf("bmcreset: cooling down for %v", e.Left) }

// Unwrap lets errors.Is(err, ErrCoolingDown) match.
func (e *CooldownError) Unwrap() error { return ErrCoolingDown }

// request is one Request in flight.
type request struct {
	id    string
	actor Actor
	corr  string
	at    time.Time
}

// Request restarts server id's BMC for actor. Order: checks that need no BMC (target,
// operator login, power interlock, restart window, cooldown reserved and the server
// marked busy, so power requests wait from here on), the "started" audit row
// (fail-closed: no row, nothing happens), operator login and discovery, the restart
// window and its row (stamped now, just before the POST), every console on the server
// ended, the one POST. A nil error means the BMC accepted the reset, or the POST got no
// answer, which is treated as sent and verified later; State reports the window.
func (s *Service) Request(ctx context.Context, id string, actor Actor) error {
	rq := request{id: id, actor: actor, corr: newCorrelationID(), at: s.cfg.Now()}
	t, prev, err := s.admit(rq)
	if err != nil {
		return err
	}
	defer s.idle(rq)
	if err = s.audit(rq, ActionReset, audit.ResultStarted, "",
		map[string]any{"deadline_after": t.Deadline.String()}); err != nil {
		s.release(rq, prev)
		return ErrAudit
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
	defer cancel()
	r, err := t.Open(ctx)
	if err != nil {
		s.release(rq, prev)
		return s.refuseBeforePost(rq, err)
	}
	defer func() { _ = r.Close(ctx) }()
	o, err := s.openWindow(ctx, rq, t.Deadline)
	if errors.Is(err, fleet.ErrUnknownServer) && s.known(id) {
		// A hot apply rebuilt the server while the window was being opened: its new
		// poller is in place now, so try once more.
		o, err = s.openWindow(ctx, rq, t.Deadline)
	}
	if err != nil {
		s.release(rq, prev)
		return s.refuseBeforePost(rq, err)
	}
	return s.post(ctx, o, r, s.endConsoles(id))
}

// admit applies the checks that need no BMC and reserves the cooldown. It returns the
// previous cooldown end so a refusal before the POST can give it back.
func (s *Service) admit(rq request) (Target, time.Time, error) {
	t, known := (*s.targets.Load())[rq.id]
	var err error
	switch {
	case !known:
		err = ErrNotConfigured
	case t.Open == nil:
		err = ErrNoOperator
	case s.powerPending(rq.id):
		err = ErrPowerPending
	}
	if err != nil {
		s.deny(rq, err)
		return Target{}, time.Time{}, err
	}
	prev, err := s.reserve(rq)
	if err != nil {
		s.deny(rq, err)
		return Target{}, time.Time{}, err
	}
	if s.powerPending(rq.id) {
		// A power action started between the first check and the reservation (review
		// N2); from the reservation on, the power service sees this request as Busy.
		s.release(rq, prev)
		s.deny(rq, ErrPowerPending)
		return Target{}, time.Time{}, ErrPowerPending
	}
	return t, prev, nil
}

// known reports whether server id is a configured target now.
func (s *Service) known(id string) bool {
	_, ok := (*s.targets.Load())[id]
	return ok
}

func (s *Service) powerPending(id string) bool {
	if s.cfg.Power == nil {
		return false
	}
	op, ok := s.cfg.Power.Last(id)
	return ok && !op.Final()
}

// reserve starts the cooldown and marks the server busy (review S-M1: the power
// interlock holds from here, during the login and discovery too) unless a window is
// open, another request is in flight or the cooldown runs.
func (s *Service) reserve(rq request) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closed:
		return time.Time{}, ErrNotConfigured
	case s.hasOpen(rq.id), s.inflight[rq.id] != "":
		return time.Time{}, ErrRestarting
	}
	prev := s.next[rq.id]
	if left := prev.Sub(rq.at); left > 0 {
		return time.Time{}, &CooldownError{Left: left}
	}
	s.next[rq.id] = rq.at.Add(s.cfg.Cooldown)
	s.inflight[rq.id] = rq.corr
	return prev, nil
}

func (s *Service) hasOpen(id string) bool {
	_, ok := s.open[id]
	return ok
}

// release gives the cooldown back (nothing was sent) and clears rq's busy mark. Both
// only when rq still holds the reservation: a late call never touches a newer request's
// (review N1).
func (s *Service) release(rq request, prev time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight[rq.id] != rq.corr {
		return
	}
	s.next[rq.id] = prev
	delete(s.inflight, rq.id)
}

// idle clears rq's busy mark when it returns (only its own); an open window keeps the
// server busy (Busy) until it closes.
func (s *Service) idle(rq request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight[rq.id] == rq.corr {
		delete(s.inflight, rq.id)
	}
}

// Busy reports whether a reset of server id is being requested or its BMC is
// restarting: power actions wait (the power service's interlock).
func (s *Service) Busy(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inflight[id] != "" || s.hasOpen(id)
}

// endConsoles ends every console on the server (each writes its own stop row with
// reason bmc_reset) and counts them.
func (s *Service) endConsoles(id string) int {
	n := 0
	for _, c := range s.cfg.Consoles {
		if c.EndForBMCReset(id) {
			n++
		}
	}
	return n
}

// openWindow opens the fleet's restart window and stores the row (result sent), both
// stamped now, just before the POST (review S-L1: the login can take a minute), so a
// crash after the POST keeps both the cooldown and the window.
func (s *Service) openWindow(ctx context.Context, rq request, deadline time.Duration) (openReset, error) {
	sentAt := s.cfg.Now()
	o := openReset{rq: rq, sentAt: sentAt, until: sentAt.Add(deadline)}
	w := fleet.RestartWindow{Since: sentAt, Until: o.until, By: rq.actor.Username}
	end := func(e fleet.RestartEnd) { s.onEnd(rq.id, rq.at, e) }
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.cfg.Fleet.ExpectRestart(rq.id, w, end); err != nil {
		return openReset{}, err
	}
	row := store.BMCResetRow{ServerID: rq.id, CorrelationID: rq.corr, RequestedAt: rq.at, SentAt: sentAt,
		RequestedBy: rq.actor.Username, ResetType: ResetType, Result: store.BMCResetSent, DeadlineAt: o.until}
	id, err := s.cfg.Store.Insert(ctx, row)
	if err != nil {
		s.cfg.Fleet.CancelRestart(rq.id)
		return openReset{}, fmt.Errorf("bmcreset: store: %w", err)
	}
	row.ID, o.rowID = id, id
	s.open[rq.id] = o
	s.last[rq.id] = recordOf(row)
	return o, nil
}

// noAnswer reports a POST that may have reached the BMC without an answer coming back:
// a timeout, or the connection lost after the request was written (review C-M2). The
// BMC may well be restarting, so the window stays open and verification decides.
func noAnswer(err error) bool {
	c := bmc.Classify(err)
	return c == bmc.ClassTimeout || c == bmc.ClassUnreachable
}

// post sends the reset. No answer is treated as sent (the row is marked unconfirmed);
// any other failure refuses the row, closes the window and keeps the cooldown.
func (s *Service) post(ctx context.Context, o openReset, r Resetter, ended int) error {
	rq := o.rq
	err := r.Reset(ctx)
	params := map[string]any{"consoles_ended": ended, "deadline": o.until.UTC().Format(time.RFC3339)}
	if err == nil || noAnswer(err) {
		params["outcome"], params["bmc_status"] = "sent", "2xx"
		if err != nil {
			params["outcome"], params["bmc_status"] = "sent_unconfirmed", string(bmc.Classify(err))
			s.markUnconfirmed(o)
		}
		s.mu.Lock()
		delete(s.refused, rq.id)
		s.count(rq.id, store.BMCResetSent)
		s.mu.Unlock()
		s.auditFinal(rq, ActionReset, audit.ResultOK, "", params)
		return nil
	}
	class := string(bmc.Classify(err))
	s.cfg.Fleet.CancelRestart(rq.id)
	s.finishRow(o.rowID, store.BMCResetRefused, time.Time{}, class, "")
	s.mu.Lock()
	delete(s.open, rq.id)
	s.last[rq.id] = Record{RequestedAt: rq.at, SentAt: o.sentAt, By: rq.actor.Username, Result: store.BMCResetRefused, Class: class}
	s.count(rq.id, store.BMCResetRefused)
	privilege := errors.Is(err, bmc.ErrPrivilege)
	if privilege {
		s.refused[rq.id] = true
	}
	s.mu.Unlock()
	s.auditFinal(rq, ActionReset, audit.ResultError, class, params)
	if privilege {
		return ErrPrivilege
	}
	return fmt.Errorf("%w: %s", ErrBMC, class)
}

// markUnconfirmed records a POST without an answer on the row and the open window.
func (s *Service) markUnconfirmed(o openReset) {
	if err := retry(func() error { return s.cfg.Store.MarkUnconfirmed(context.Background(), o.rowID) }); err != nil &&
		!errors.Is(err, store.ErrNotFound) {
		s.cfg.Logger.Error("bmc reset: marking the row unconfirmed failed", "row", o.rowID, "err", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.open[o.rq.id]; ok && cur.rowID == o.rowID {
		cur.unconfirmed = true
		s.open[o.rq.id] = cur
	}
}

// refuseBeforePost records a failure before anything was sent (login, discovery, the
// window or its row); the cooldown was given back by the caller. The row carries
// after_started, so the notification tap closes the "requested" alert (review S-L4).
func (s *Service) refuseBeforePost(rq request, err error) error {
	params := map[string]any{"after_started": true}
	switch {
	case errors.Is(err, bmc.ErrUnsupported):
		_ = s.audit(rq, ActionReset, audit.ResultDenied, "not_offered", params)
		return ErrUnsupported
	case errors.Is(err, fleet.ErrRestarting):
		_ = s.audit(rq, ActionReset, audit.ResultDenied, "restarting", params)
		return ErrRestarting
	case errors.Is(err, fleet.ErrUnknownServer):
		_ = s.audit(rq, ActionReset, audit.ResultDenied, "not_configured", params)
		return ErrNotConfigured
	}
	class := classOf(err)
	_ = s.audit(rq, ActionReset, audit.ResultError, class, params)
	return fmt.Errorf("%w: %s", ErrBMC, class)
}

func classOf(err error) string {
	switch {
	case errors.Is(err, fleet.ErrPaused):
		return string(bmc.ClassTLS)
	case bmc.Classify(err) == bmc.ClassOther:
		return "unsupported"
	default:
		return string(bmc.Classify(err))
	}
}

// deny audits a refusal before any work, with its class.
func (s *Service) deny(rq request, err error) {
	_ = s.audit(rq, ActionReset, audit.ResultDenied, denyClass(err), map[string]any{"reset_type": ResetType})
}

func denyClass(err error) string {
	switch {
	case errors.Is(err, ErrNoOperator):
		return "no_operator"
	case errors.Is(err, ErrPowerPending):
		return "power_pending"
	case errors.Is(err, ErrRestarting):
		return "restarting"
	case errors.Is(err, ErrCoolingDown):
		return "cooldown"
	default:
		return "not_configured"
	}
}

// auditFinal records a final row (ok, error, verified), retrying a failed write so a
// transient database error does not lose it; a write that keeps failing is logged as
// an error naming the outcome (review S-L4).
func (s *Service) auditFinal(rq request, action, result, class string, params map[string]any) {
	if err := retry(func() error { return s.audit(rq, action, result, class, params) }); err != nil {
		s.cfg.Logger.Error("bmc reset: the final audit row was not written", "server", rq.id, "action", action,
			"result", result, "class", class)
	}
}

// retry runs fn up to finalAttempts times with a short, growing pause.
func retry(fn func() error) error {
	var err error
	for i := range finalAttempts {
		if err = fn(); err == nil {
			return nil
		}
		time.Sleep(time.Duration(i+1) * finalRetryPause)
	}
	return err
}

// audit records one entry for rq.
func (s *Service) audit(rq request, action, result, class string, params map[string]any) error {
	if params == nil {
		params = map[string]any{}
	}
	params["reset_type"] = ResetType
	_, err := s.cfg.Audit.Record(context.Background(), audit.Entry{CorrelationID: rq.corr,
		Principal: rq.actor.Username, AuthMethod: rq.actor.AuthMethod, Role: rq.actor.Role, SrcIP: rq.actor.SrcIP,
		ServerID: rq.id, Action: action, Params: params, Result: result, ErrorClass: class})
	if err != nil {
		s.cfg.Logger.Error("bmc reset audit record failed", "server", rq.id, "result", result, "err", err)
	}
	return err
}

func newCorrelationID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

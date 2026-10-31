package console

import (
	"context"
	"errors"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/bmc/bmcssh"
)

// statusWait bounds the final status message to a stalled browser.
const statusWait = 2 * time.Second

// ServeSerial redeems a ticket and runs one serial console session on peer until it
// ends. Errors before the session starts are returned (and audited where a user is
// known). The caller closes the WebSocket afterwards.
func (s *SerialService) ServeSerial(ctx context.Context, ticket, serverID string, session [32]byte,
	peer SerialPeer, check Watchdog) error {
	g, err := s.tickets.redeem(ticket, serverID, session)
	if err != nil {
		return err
	}
	if err = s.ready(serverID); err != nil {
		s.auditDenied(ctx, g, err)
		return err
	}
	info := Active{SessionID: newSessionID(), ServerID: serverID, UserID: g.UserID, Username: g.Username, Since: s.cfg.Now()}
	sctx, release, prev, err := s.broker.claim(ctx, info, g.Takeover)
	if err != nil {
		s.auditDenied(ctx, g, err)
		return err
	}
	defer release()
	if prev != nil {
		_ = s.audit(ctx, g, info.SessionID, "console.serial.takeover", audit.ResultOK, "", map[string]any{
			"previous_user": prev.Username, "previous_session": prev.SessionID,
			"previous_duration_s": int64(s.cfg.Now().Sub(prev.Since) / time.Second)})
	}
	if err = s.audit(ctx, g, info.SessionID, "console.serial.start", audit.ResultStarted, "", nil); err != nil {
		return err // fail closed: no console without its audit row
	}
	return s.run(sctx, g, info, peer, check)
}

func (s *SerialService) run(ctx context.Context, g Grant, info Active, peer SerialPeer, check Watchdog) error {
	t, ok := s.target(g.ServerID)
	if !ok { // removed between the ticket and the connection
		s.auditStop(ctx, g, info, serialResult{}, "not_configured")
		return ErrSerialNotConfigured
	}
	link, err := s.connect(ctx, t)
	if err != nil {
		class := bmcssh.Classify(err)
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusWait)
		sendStatus(wctx, peer, statusMsg{Type: "error", Class: class})
		cancel()
		s.auditStop(ctx, g, info, serialResult{}, class)
		return err
	}
	lim := relayLimits{idle: s.cfg.IdleTimeout, max: s.cfg.MaxSession, check: min(s.cfg.CheckEvery, s.cfg.IdleTimeout)}
	res := relaySerial(ctx, peer, link, lim, check)
	s.auditStop(ctx, g, info, res, "")
	return nil
}

// connect opens the BMC console. A rejected login starts the cooldown, so the app
// never hammers the BMC (and its account lockout) with failing logins.
func (s *SerialService) connect(ctx context.Context, t SerialTarget) (SerialLink, error) {
	link, err := s.cfg.Open(ctx, t, TermSize{Cols: bmcssh.DefaultCols, Rows: bmcssh.DefaultRows})
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	if err != nil {
		s.last[t.ServerID] = SerialAttempt{At: now, Class: bmcssh.Classify(err)}
		if errors.Is(err, bmcssh.ErrAuth) {
			s.rejected[t.ServerID] = now
		}
		return nil, err
	}
	s.last[t.ServerID] = SerialAttempt{At: now}
	delete(s.rejected, t.ServerID)
	return link, nil
}

func (s *SerialService) audit(ctx context.Context, g Grant, corr, action, result, class string, params map[string]any) error {
	return recordAudit(ctx, s.cfg.Audit, s.cfg.Logger, g, corr, action, result, class, params)
}

func (s *SerialService) auditDenied(ctx context.Context, g Grant, err error) {
	_ = s.audit(ctx, g, "", "console.serial.start", audit.ResultDenied, SerialErrorClass(err), nil)
}

// SerialErrorClass is the audit class of an Issue or ServeSerial refusal.
func SerialErrorClass(err error) string {
	switch {
	case errors.Is(err, ErrInUse):
		return "in_use"
	case errors.Is(err, ErrCoolingDown):
		return "cooldown"
	case errors.Is(err, ErrSerialNoLogin):
		return "no_credential"
	case errors.Is(err, ErrSerialNoHostKey):
		return "no_host_key"
	case errors.Is(err, ErrSerialUnsupported):
		return "unsupported"
	default:
		return "unavailable"
	}
}

func (s *SerialService) auditStop(ctx context.Context, g Grant, info Active, res serialResult, failClass string) {
	result, reason := audit.ResultOK, string(res.reason)
	if failClass != "" {
		result, reason = audit.ResultError, "connect_failed"
	}
	_ = s.audit(ctx, g, info.SessionID, "console.serial.stop", result, failClass, map[string]any{
		"reason": reason, "duration_s": int64(s.cfg.Now().Sub(info.Since) / time.Second),
		"bytes_to_browser": res.toBrowser, "bytes_to_bmc": res.toBMC,
		"dropped_bytes": res.dropped, "breaks": res.breaks})
}

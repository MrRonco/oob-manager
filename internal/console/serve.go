package console

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/console/rfb"
)

var (
	errBMCAuth         = errors.New("console: the BMC rejected the VNC password")
	errBMCProtocol     = errors.New("console: BMC RFB handshake failed")
	errBrowserProtocol = errors.New("console: browser RFB handshake failed")
)

// Watchdog is called periodically while a console runs; a non-nil error ends it
// (ErrSessionEnded, ErrStepUpExpired, ErrForbidden name the reason).
type Watchdog func(ctx context.Context) error

// Serve redeems a ticket and runs one console session on browser (an RFB byte stream,
// normally a WebSocket wrapped as a net.Conn) until it ends. It closes browser. Errors
// before the session starts are returned (and audited where a user is known).
func (s *Service) Serve(ctx context.Context, ticket, serverID string, session [32]byte, browser net.Conn, check Watchdog) error {
	defer browser.Close()
	g, err := s.tickets.redeem(ticket, serverID, session)
	if err != nil {
		return err
	}
	if err = s.ready(serverID); err != nil {
		s.auditFail(ctx, g, "", err)
		return err
	}
	info := Active{SessionID: newSessionID(), ServerID: serverID, UserID: g.UserID, Username: g.Username, Since: s.cfg.Now()}
	sctx, release, prev, err := s.broker.claim(ctx, info, g.Takeover)
	if err != nil {
		s.auditFail(ctx, g, "", err)
		return err
	}
	defer release()
	if prev != nil {
		s.auditTakeover(ctx, g, info, *prev)
	}
	if err = s.audit(ctx, g, info.SessionID, "console.vnc.start", audit.ResultStarted, "", nil); err != nil {
		return err // fail closed: no console without its audit row
	}
	return s.run(sctx, g, info, browser, check)
}

func (s *Service) run(ctx context.Context, g Grant, info Active, browser net.Conn, check Watchdog) error {
	t, ok := s.target(g.ServerID)
	if !ok { // removed between the ticket and the connection
		s.auditStop(ctx, g, info, relayResult{}, "not_configured")
		return ErrNotConfigured
	}
	bmcConn, si, err := s.connect(ctx, t)
	if err != nil {
		s.auditStop(ctx, g, info, relayResult{}, classify(err))
		return err
	}
	if t.LowColour {
		si = si.WithName(lowColourName)
	}
	_ = browser.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := rfb.ServerHandshake(browser, si); err != nil {
		_ = bmcConn.Close()
		err = fmt.Errorf("%w: %w", errBrowserProtocol, err)
		s.auditStop(ctx, g, info, relayResult{}, classify(err))
		return err
	}
	_ = browser.SetDeadline(time.Time{})
	lim := relayLimits{idle: s.cfg.IdleTimeout, max: s.cfg.MaxSession, check: min(s.cfg.CheckEvery, s.cfg.IdleTimeout)}
	res := relay(ctx, browser, bmcConn, rfb.FilterConfig{SafeEncodings: t.SafeEncodings}, lim, check)
	s.auditStop(ctx, g, info, res, "")
	return nil
}

// connect dials the BMC and authenticates. A rejected password starts the cooldown, so
// the app never hammers the BMC with failing logins.
func (s *Service) connect(ctx context.Context, t Target) (net.Conn, rfb.ServerInit, error) {
	c, err := dialTarget(ctx, s.cfg.Dial, t)
	if err != nil {
		s.recordProbe(t.ServerID, Probe{State: classifyDial(err), CheckedAt: s.cfg.Now()})
		return nil, rfb.ServerInit{}, err
	}
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	pw := t.Password.Bytes()
	si, err := rfb.ClientHandshake(c, pw)
	clear(pw)
	if err != nil {
		_ = c.Close()
		if errors.Is(err, rfb.ErrAuthFailed) {
			s.mu.Lock()
			s.rejected[t.ServerID] = s.cfg.Now()
			s.mu.Unlock()
			return nil, rfb.ServerInit{}, fmt.Errorf("%w: %w", errBMCAuth, err)
		}
		return nil, rfb.ServerInit{}, fmt.Errorf("%w: %w", errBMCProtocol, err)
	}
	_ = c.SetDeadline(time.Time{})
	s.mu.Lock()
	delete(s.rejected, t.ServerID)
	s.mu.Unlock()
	s.recordProbe(t.ServerID, Probe{State: ProbeOK, CheckedAt: s.cfg.Now()})
	return c, si, nil
}

func (s *Service) audit(ctx context.Context, g Grant, corr, action, result, class string, params map[string]any) error {
	return recordAudit(ctx, s.cfg.Audit, s.cfg.Logger, g, corr, action, result, class, params)
}

// recordAudit writes one console audit row (graphical and serial) for grant g.
func recordAudit(ctx context.Context, aud Auditor, log *slog.Logger, g Grant, corr, action, result, class string,
	params map[string]any) error {
	_, err := aud.Record(context.WithoutCancel(ctx), audit.Entry{CorrelationID: corr, Principal: g.Username,
		AuthMethod: "local", Role: g.Role, SrcIP: g.SrcIP, ServerID: g.ServerID, Action: action,
		Params: params, Result: result, ErrorClass: class})
	if err != nil {
		log.Error("console audit failed", "action", action, "server", g.ServerID, "err", err)
	}
	return err
}

func (s *Service) auditFail(ctx context.Context, g Grant, corr string, err error) {
	class := "unavailable"
	switch {
	case errors.Is(err, ErrInUse):
		class = "in_use"
	case errors.Is(err, ErrCoolingDown):
		class = "cooldown"
	case errors.Is(err, ErrNoPassword):
		class = "no_credential"
	}
	_ = s.audit(ctx, g, corr, "console.vnc.start", audit.ResultDenied, class, nil)
}

func (s *Service) auditTakeover(ctx context.Context, g Grant, info, prev Active) {
	_ = s.audit(ctx, g, info.SessionID, "console.vnc.takeover", audit.ResultOK, "", map[string]any{
		"previous_user": prev.Username, "previous_session": prev.SessionID,
		"previous_duration_s": int64(s.cfg.Now().Sub(prev.Since) / time.Second)})
}

func (s *Service) auditStop(ctx context.Context, g Grant, info Active, res relayResult, failClass string) {
	result, reason := audit.ResultOK, string(res.reason)
	if failClass != "" {
		result, reason = audit.ResultError, "connect_failed"
	}
	_ = s.audit(ctx, g, info.SessionID, "console.vnc.stop", result, failClass, map[string]any{
		"reason": reason, "duration_s": int64(s.cfg.Now().Sub(info.Since) / time.Second),
		"bytes_to_browser": res.toBrowser, "bytes_to_bmc": res.toBMC, "dropped_messages": res.dropped})
}

package ui

import (
	"context"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/console"
	"oob-manager/internal/console/rfb"
)

// wsReadLimit bounds one WebSocket message from the browser (noVNC sends small
// messages; the largest allowed is a clipboard update).
const wsReadLimit = rfb.DefaultMaxCutText + 4096

const maxTicketLen = 64

// consoleWS upgrades GET /servers/{id}/console/ws?ticket=… after checking the session
// cookie, the role, a fresh step-up and the Origin; the ticket (single use, bound to
// this session and server) is redeemed by the broker. The session then runs until it
// ends; the watchdog re-checks the session every few seconds.
func (s *server) consoleWS(w http.ResponseWriter, r *http.Request) {
	id, ticket := r.PathValue("id"), r.URL.Query().Get("ticket")
	if s.d.Consoles == nil || !serverIDPattern.MatchString(id) || ticket == "" || len(ticket) > maxTicketLen {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	token, ok := auth.SessionTokenFromRequest(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ident, err := s.d.Auth.Authenticate(r.Context(), token)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err = s.d.Authorize(ident.Principal(), authz.ConsoleVNC, s.d.Auth.StepUpFresh(ident.Session)); err != nil {
		_ = s.record(r, audit403(ident, err))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// The server's read/write timeouts would cut a hijacked connection; the console
	// enforces its own idle and maximum limits instead.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"binary"},
		OriginPatterns: s.originPatterns()})
	if err != nil {
		return // Accept has answered (403 on a foreign Origin)
	}
	c.SetReadLimit(wsReadLimit)
	ctx, cancel := context.WithCancel(context.WithoutCancel(r.Context()))
	defer cancel()
	conn := websocket.NetConn(ctx, c, websocket.MessageBinary)
	err = s.d.Consoles.Serve(ctx, ticket, id, console.SessionHash(token), conn, s.sessionWatchdog(token, authz.ConsoleVNC))
	if err != nil {
		s.d.Logger.Info("console not started", "server", id, "err", err)
	}
}

// sessionWatchdog ends a running console (graphical or serial) when the browser session
// ends (logout, idle or absolute expiry, rotation), the user loses the role for action,
// or (when configured) the step-up window lapses.
func (s *server) sessionWatchdog(token string, action authz.Action) console.Watchdog {
	return func(ctx context.Context) error {
		id, err := s.d.Auth.Authenticate(ctx, token)
		if err != nil {
			return console.ErrSessionEnded
		}
		if s.d.Authorize(id.Principal(), action, true) != nil {
			return console.ErrForbidden
		}
		if s.d.CloseConsoleOnStepUpExpiry && !s.d.Auth.StepUpFresh(id.Session) {
			return console.ErrStepUpExpired
		}
		return nil
	}
}

// originPatterns adds public_url's host to the request host (always allowed).
func (s *server) originPatterns() []string {
	if h := publicHost(s.d.PublicURL); h != "" {
		return []string{h}
	}
	return nil
}

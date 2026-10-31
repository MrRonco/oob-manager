package ui

import (
	"context"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/console"
)

// serialSubprotocol names the serial socket's protocol: binary messages are terminal
// bytes, text messages the JSON control protocol (internal/console serial_proto.go).
const serialSubprotocol = "oob-serial.v1"

// serialReadLimit bounds one browser message (a paste is at most console.MaxSerialInput).
const serialReadLimit = console.MaxSerialInput + 1024

// serialWS upgrades GET /servers/{id}/serial/ws?ticket=… after the same checks as the
// graphical console (cookie, role + fresh step-up, Origin); the broker redeems the
// single-use ticket bound to this session and server.
func (s *server) serialWS(w http.ResponseWriter, r *http.Request) {
	id, ticket := r.PathValue("id"), r.URL.Query().Get("ticket")
	if s.d.Serial == nil || !serverIDPattern.MatchString(id) || ticket == "" || len(ticket) > maxTicketLen {
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
	if err = s.d.Authorize(ident.Principal(), authz.ConsoleSerial, s.d.Auth.StepUpFresh(ident.Session)); err != nil {
		_ = s.record(r, audit403(ident, err))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{serialSubprotocol},
		OriginPatterns: s.originPatterns()})
	if err != nil {
		return // Accept has answered (403 on a foreign Origin)
	}
	c.SetReadLimit(serialReadLimit)
	ctx, cancel := context.WithCancel(context.WithoutCancel(r.Context()))
	defer cancel()
	err = s.d.Serial.ServeSerial(ctx, ticket, id, console.SessionHash(token), wsPeer{c}, s.sessionWatchdog(token, authz.ConsoleSerial))
	if err != nil {
		s.d.Logger.Info("serial console not started", "server", id, "err", err)
	}
	_ = c.Close(websocket.StatusNormalClosure, "")
}

// wsPeer adapts a WebSocket to console.SerialPeer.
type wsPeer struct{ c *websocket.Conn }

func (p wsPeer) Read(ctx context.Context) (console.MessageType, []byte, error) {
	typ, b, err := p.c.Read(ctx)
	if err != nil {
		return 0, nil, err
	}
	if typ == websocket.MessageText {
		return console.MessageText, b, nil
	}
	return console.MessageBinary, b, nil
}

func (p wsPeer) Write(ctx context.Context, typ console.MessageType, b []byte) error {
	t := websocket.MessageBinary
	if typ == console.MessageText {
		t = websocket.MessageText
	}
	return p.c.Write(ctx, t, b)
}

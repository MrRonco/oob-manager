package ui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/console"
)

func wsDial(t *testing.T, srv *httptest.Server, path, cookie, origin string) (*websocket.Conn, int, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	hdr := http.Header{}
	if cookie != "" {
		hdr.Set("Cookie", auth.SessionCookieName+"="+cookie)
	}
	if origin != "" {
		hdr.Set("Origin", origin)
	}
	c, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+path,
		&websocket.DialOptions{HTTPHeader: hdr, Subprotocols: []string{"binary"}})
	code := 0
	if resp != nil {
		code = resp.StatusCode
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}
	return c, code, err
}

func TestConsoleWebSocket(t *testing.T) {
	h, c, fc, _ := consoleHarness(t, authz.RoleAdmin)
	srv := httptest.NewServer(h.handler)
	t.Cleanup(srv.Close)
	cookie := c.jar[auth.SessionCookieName]
	conn, code, err := wsDial(t, srv, "/servers/r730xd/console/ws?ticket=tkt-r730xd", cookie, srv.URL)
	if err != nil {
		t.Fatalf("dial: %v (%d)", err, code)
	}
	if conn.Subprotocol() != "binary" {
		t.Errorf("subprotocol %q", conn.Subprotocol())
	}
	ctx := context.Background()
	if typ, b, err := conn.Read(ctx); err != nil || typ != websocket.MessageBinary || string(b) != "hello" {
		t.Fatalf("read %v %q %v", typ, b, err)
	}
	_ = conn.Write(ctx, websocket.MessageBinary, []byte("ping"))
	if _, b, err := conn.Read(ctx); err != nil || string(b) != "ping" {
		t.Fatalf("echo %q %v", b, err)
	}
	waitCond(t, func() bool { return len(fc.calls()) == 1 })
	call := fc.calls()[0]
	if call.ticket != "tkt-r730xd" || call.server != "r730xd" || call.session != console.SessionHash(cookie) {
		t.Errorf("Serve called with %+v", call)
	}
	// The watchdog: fine now; ends with the session; and, when configured, with step-up.
	if err := call.check(ctx); err != nil {
		t.Errorf("watchdog on a live session: %v", err)
	}
	h.clock.Advance(6 * time.Minute)
	if err := call.check(ctx); err != nil {
		t.Errorf("stale step-up must not end the console by default: %v", err)
	}
	_ = h.authn.Logout(ctx, cookie)
	if err := call.check(ctx); !errors.Is(err, console.ErrSessionEnded) {
		t.Errorf("after logout: %v", err)
	}
	_ = conn.CloseNow()
}

func TestConsoleWebSocketRefusals(t *testing.T) {
	h, c, _, _ := consoleHarness(t, authz.RoleAdmin)
	srv := httptest.NewServer(h.handler)
	t.Cleanup(srv.Close)
	cookie := c.jar[auth.SessionCookieName]
	cases := map[string]struct {
		path, cookie, origin string
		want                 int
	}{
		"no cookie":      {"/servers/r730xd/console/ws?ticket=t", "", "", http.StatusUnauthorized},
		"bad cookie":     {"/servers/r730xd/console/ws?ticket=t", "garbage", "", http.StatusUnauthorized},
		"no ticket":      {"/servers/r730xd/console/ws", cookie, "", http.StatusNotFound},
		"long ticket":    {"/servers/r730xd/console/ws?ticket=" + strings.Repeat("a", 65), cookie, "", http.StatusNotFound},
		"bad server id":  {"/servers/R!/console/ws?ticket=t", cookie, "", http.StatusNotFound},
		"foreign origin": {"/servers/r730xd/console/ws?ticket=t", cookie, "https://evil.example", http.StatusForbidden},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, code, err := wsDial(t, srv, tc.path, tc.cookie, tc.origin); err == nil || code != tc.want {
				t.Fatalf("code %d err %v, want %d", code, err, tc.want)
			}
		})
	}
	h.clock.Advance(6 * time.Minute) // step-up stale: no upgrade
	if _, code, err := wsDial(t, srv, "/servers/r730xd/console/ws?ticket=t", cookie, ""); err == nil || code != http.StatusForbidden {
		t.Fatalf("stale step-up: %d %v", code, err)
	}
}

func TestConsoleWatchdogStrictStepUp(t *testing.T) {
	h, c, fc, _ := consoleHarness(t, authz.RoleAdmin, func(d *Deps) { d.CloseConsoleOnStepUpExpiry = true })
	srv := httptest.NewServer(h.handler)
	t.Cleanup(srv.Close)
	fc.serveErr = errors.New("refused")
	_, _, _ = wsDial(t, srv, "/servers/r730xd/console/ws?ticket=t", c.jar[auth.SessionCookieName], "")
	waitCond(t, func() bool { return len(fc.calls()) == 1 })
	check := fc.calls()[0].check
	if err := check(context.Background()); err != nil {
		t.Fatalf("fresh: %v", err)
	}
	h.clock.Advance(6 * time.Minute)
	if err := check(context.Background()); !errors.Is(err, console.ErrStepUpExpired) {
		t.Errorf("strict step-up: %v", err)
	}
}

func waitCond(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

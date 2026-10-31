//go:build e2e

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"oob-manager/internal/auth"
	"oob-manager/internal/bmc/redfishmock"
)

// checkSerial: R730XD serial console end to end (ticket → WebSocket → broker → bmcssh with
// the legacy iDRAC8 algorithms → fake BMC running `console com2`), echo, resize, break and
// quit; the operator password never crosses the socket; a replayed ticket opens nothing.
func checkSerial(t *testing.T, b browser, s *stack) {
	expectPage(t, b.get("/servers/r730xd"), `<h2 id="sc-h">Serial console</h2>`, `href="/servers/r730xd/serial">`,
		"idrac8_legacy_ssh")
	ticket := startSerial(t, b, "r730xd")
	c := dialSerial(t, b, s, "r730xd", ticket)
	var got bytes.Buffer
	readSerial(t, c, &got, `{"type":"connected"}`)
	readSerial(t, c, &got, "Connected to Serial Device 2")
	ctx := context.Background()
	_ = c.Write(ctx, websocket.MessageText, []byte(`{"type":"resize","cols":120,"rows":40}`))
	_ = c.Write(ctx, websocket.MessageBinary, []byte("hello e2e\r"))
	readSerial(t, c, &got, "hello e2e\r")
	_ = c.Write(ctx, websocket.MessageText, []byte(`{"type":"break"}`))
	readSerial(t, c, &got, "<BREAK>")
	_ = c.Write(ctx, websocket.MessageText, []byte(`{"type":"quit"}`))
	readSerial(t, c, &got, `{"type":"end","reason":"quit"}`)
	fake := s.ssh["r730xd"]
	waitFor(t, "console ended at the BMC", func() bool { return fake.Active() == 0 })
	if want := []string{"pty-req", "exec", "window-change", "break"}; !slices.Equal(fake.RequestTypes(), want) {
		t.Errorf("BMC requests %v, want %v", fake.RequestTypes(), want)
	}
	if !bytes.Equal(fake.Input(), []byte("hello e2e\r\x1c")) {
		t.Errorf("BMC input %q", fake.Input())
	}
	if bytes.Contains(got.Bytes(), []byte(redfishmock.OperatorPassword)) {
		t.Fatal("the operator password crossed the WebSocket")
	}
	// A used ticket opens nothing: the socket closes without a console.
	before := fake.Sessions()
	replay := dialSerial(t, b, s, "r730xd", ticket)
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, _, err := replay.Read(rctx); websocket.CloseStatus(err) != websocket.StatusNormalClosure {
		t.Errorf("replayed ticket: %v", err)
	}
	if fake.Sessions() != before {
		t.Error("replayed ticket reached the BMC")
	}
	checkSilentSerial(t, b, s)
}

// checkSilentSerial: the R240 host sends nothing (no BIOS serial redirection); the
// console still connects and keystrokes reach the BMC.
func checkSilentSerial(t *testing.T, b browser, s *stack) {
	t.Helper()
	c := dialSerial(t, b, s, "r240", startSerial(t, b, "r240"))
	var got bytes.Buffer
	readSerial(t, c, &got, `{"type":"connected"}`)
	_ = c.Write(context.Background(), websocket.MessageBinary, []byte("\r"))
	waitFor(t, "Enter at the silent BMC", func() bool { return bytes.Equal(s.ssh["r240"].Input(), []byte("\r")) })
	_ = c.Close(websocket.StatusNormalClosure, "")
}

func startSerial(t *testing.T, b browser, id string) string {
	t.Helper()
	path := "/servers/" + id + "/serial"
	form := b.get(path)
	p := b.post(path, url.Values{"csrf_token": {formCSRF(t, form, path)}})
	m := ticketAttr.FindStringSubmatch(p.body)
	if p.status != http.StatusOK || m == nil {
		t.Fatalf("serial start %s: %d %s", id, p.status, p.body)
	}
	return m[1]
}

func dialSerial(t *testing.T, b browser, s *stack, id, ticket string) *websocket.Conn {
	t.Helper()
	pem, err := os.ReadFile(s.certPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	hdr := http.Header{"Cookie": {auth.SessionCookieName + "=" + sessionCookie(t, b)}, "Origin": {b.base}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	wsURL := "wss" + strings.TrimPrefix(b.base, "https") + "/servers/" + id + "/serial/ws?ticket=" + ticket
	c, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: hc, HTTPHeader: hdr,
		Subprotocols: []string{"oob-serial.v1"}})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("serial websocket: %v", err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	return c
}

// readSerial reads messages into got until want appears.
func readSerial(t *testing.T, c *websocket.Conn, got *bytes.Buffer, want string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for !strings.Contains(got.String(), want) {
		_, p, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("waiting for %q: %v (got %q)", want, err, got.String())
		}
		got.Write(p)
	}
}

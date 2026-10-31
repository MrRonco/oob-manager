//go:build e2e

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"oob-manager/internal/auth"
	"oob-manager/internal/console/rfb"
	"oob-manager/internal/console/rfbtest"
)

var ticketAttr = regexp.MustCompile(`data-ticket="([A-Za-z0-9_-]+)"`)

// recorder keeps every byte the "browser" receives over the WebSocket.
type recorder struct {
	net.Conn
	got bytes.Buffer
}

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.got.Write(p[:n])
	return n, err
}

func (r *recorder) Write(p []byte) (int, error) {
	r.got.Write(p)
	return r.Conn.Write(p)
}

// checkConsole: R730XD VNC console end to end (ticket → WebSocket → relay → fake VNC
// server) and the R240 native console launch.
func checkConsole(t *testing.T, b browser, s *stack) {
	expectPage(t, b.get("/servers/r730xd"), "Graphical console", `href="/servers/r730xd/console">Open console</a>`,
		"VNC over TLS to the BMC.")
	expectPage(t, b.get("/servers/r730xd/console"), ">Connect</button>")
	ticket := startConsole(t, b)
	conn := dialConsole(t, b, s, ticket)
	rec := &recorder{Conn: conn}
	_ = rec.SetDeadline(time.Now().Add(10 * time.Second))
	si, err := rfb.ClientHandshake(rec, nil) // no password: the app offers None
	if err != nil {
		t.Fatalf("browser RFB handshake: %v", err)
	}
	if si.Width != 320 || si.Name != "Intel(r) AMT KVM" {
		t.Errorf("ServerInit %+v (iDRAC8 low-colour quirk expected)", si)
	}
	sendMessages(t, rec)
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(rec, hdr); err != nil || hdr[0] != 0 {
		t.Fatalf("no framebuffer update: %v %v", hdr, err)
	}
	waitFor(t, "Ctrl-Alt-Del at the BMC", func() bool { return len(s.vnc.Keys()) == 6 })
	if got := s.vnc.Encodings(); len(got) != 1 || !slices.Equal(got[0], []int32{rfb.EncRaw, rfb.EncCopyRect, rfb.EncDesktopSize}) {
		t.Errorf("BMC encodings %v (iDRAC8 safe-encodings quirk expected)", got)
	}
	_, _ = rec.Write([]byte{255, 0, 0, 0}) // not allowlisted: the relay ends the session
	_, _ = io.Copy(io.Discard, rec)
	if slices.Contains(s.vnc.MessageTypes(), 255) {
		t.Error("a disallowed message reached the BMC")
	}
	if bytes.Contains(rec.got.Bytes(), []byte(rfbtest.Password)) {
		t.Fatal("the VNC password crossed the WebSocket")
	}
	checkTicketReplay(t, b, s, ticket)
	checkKVMLaunch(t, b, s)
}

func startConsole(t *testing.T, b browser) string {
	t.Helper()
	form := b.get("/servers/r730xd/console")
	p := b.post("/servers/r730xd/console", url.Values{"csrf_token": {formCSRF(t, form, "/servers/r730xd/console")}})
	m := ticketAttr.FindStringSubmatch(p.body)
	if p.status != http.StatusOK || m == nil {
		t.Fatalf("console start: %d %s", p.status, p.body)
	}
	return m[1]
}

func sendMessages(t *testing.T, w io.Writer) {
	t.Helper()
	encs := []int32{rfb.EncTight, rfb.EncZRLE, rfb.EncRaw, rfb.EncCopyRect, rfb.EncDesktopSize, -258, -308, -1063131698}
	msg := binary.BigEndian.AppendUint16([]byte{rfb.MsgSetEncodings, 0}, uint16(len(encs))) //nolint:gosec // G115: 8 test encodings
	for _, e := range encs {
		msg = binary.BigEndian.AppendUint32(msg, uint32(e)) //nolint:gosec // two's complement on purpose
	}
	msg = append(msg, rfb.MsgFramebufferUpdateRequest, 0, 0, 0, 0, 0, 1, 64, 0, 200)
	for _, k := range []struct {
		down bool
		sym  uint32
	}{{true, 0xffe3}, {true, 0xffe9}, {true, 0xffff}, {false, 0xffff}, {false, 0xffe9}, {false, 0xffe3}} {
		ev := []byte{rfb.MsgKeyEvent, 0, 0, 0}
		if k.down {
			ev[1] = 1
		}
		msg = append(msg, binary.BigEndian.AppendUint32(ev, k.sym)...)
	}
	if _, err := w.Write(msg); err != nil {
		t.Fatal(err)
	}
}

func sessionCookie(t *testing.T, b browser) string {
	t.Helper()
	u, _ := url.Parse(b.base)
	for _, c := range b.c.Jar.Cookies(u) {
		if c.Name == auth.SessionCookieName {
			return c.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

func dialConsole(t *testing.T, b browser, s *stack, ticket string) net.Conn {
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
	wsURL := "wss" + strings.TrimPrefix(b.base, "https") + "/servers/r730xd/console/ws?ticket=" + ticket
	c, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: hc, HTTPHeader: hdr, Subprotocols: []string{"binary"}})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("websocket: %v", err)
	}
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary)
}

// checkTicketReplay: a used ticket opens nothing (the socket closes before any RFB).
func checkTicketReplay(t *testing.T, b browser, s *stack, ticket string) {
	t.Helper()
	before := s.vnc.Stats().AuthOK
	conn := dialConsole(t, b, s, ticket)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, _ := io.Copy(io.Discard, conn); n != 0 {
		t.Errorf("replayed ticket produced %d bytes", n)
	}
	if s.vnc.Stats().AuthOK != before {
		t.Error("replayed ticket reached the BMC")
	}
}

func checkKVMLaunch(t *testing.T, b browser, s *stack) {
	t.Helper()
	srv := b.get("/servers/r240")
	expectPage(t, srv, "Open native iDRAC console")
	tok := regexp.MustCompile(`action="/servers/r240/console/kvm-launch" target="_blank">\s*<input type="hidden" name="csrf_token" value="([^"]+)"`).FindStringSubmatch(srv.body)
	if tok == nil {
		t.Fatal("no KVM launch form")
	}
	p := b.post("/servers/r240/console/kvm-launch", url.Values{"csrf_token": {tok[1]}})
	expectPage(t, p, `href="https://192.0.2.11/console?`, "tempUsername=tmpkvm1")
	if p.header.Get("Cache-Control") != "no-store" || s.mocks["r240"].KVMStats().Launches != 1 {
		t.Errorf("kvm launch: cache %q stats %+v", p.header.Get("Cache-Control"), s.mocks["r240"].KVMStats())
	}
}

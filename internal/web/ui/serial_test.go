package ui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
	"oob-manager/internal/console"
)

func serialHarness(t *testing.T, role authz.Role, tweak ...func(*Deps)) (*harness, *client, *fakeSerial) {
	t.Helper()
	fs := newFakeSerial()
	all := append([]func(*Deps){func(d *Deps) {
		d.Serial = fs
		d.BMCWebURL = func(string) string { return "https://192.0.2.10/" }
	}}, tweak...)
	h := newHarness(t, all...)
	secret := h.addUser("boss", role, true)
	c := h.client("192.0.2.5")
	c.login("boss", secret)
	return h, c, fs
}

func TestServerPageShowsSerialCard(t *testing.T) {
	t.Parallel()
	_, admin, _ := serialHarness(t, authz.RoleAdmin)
	result(admin.get("/servers/r730xd")).status(t, http.StatusOK).contains(t,
		`<h2 id="sc-h">Serial console</h2>`, `href="/servers/r730xd/serial">`, "Open serial console",
		"idrac8_legacy_ssh", silentHint, `<a class="mi" href="/servers/r730xd/serial">`)
	// r240 has no serial console configured and no capability data: "Not checked yet".
	result(admin.get("/servers/r240")).contains(t, "Not checked yet").lacks(t, "/servers/r240/serial")

	_, viewer, _ := serialHarness(t, authz.RoleViewer)
	result(viewer.get("/servers/r730xd")).contains(t, "Serial console", "Needs the admin role.").
		lacks(t, "/serial\">", "Open serial console")
}

func TestSerialPageNeedsAdminAndFreshStepUp(t *testing.T) {
	t.Parallel()
	h, admin, _ := serialHarness(t, authz.RoleAdmin)
	result(admin.get("/servers/r730xd/serial")).status(t, http.StatusOK).
		contains(t, `action="/servers/r730xd/serial"`, ">Connect</button>").
		lacks(t, "data-ticket", "serial.js")
	h.clock.Advance(6 * time.Minute)
	result(admin.get("/servers/r730xd/serial")).status(t, http.StatusSeeOther).
		location(t, "/stepup?next=%2Fservers%2Fr730xd%2Fserial")
	if _, ok := h.audit.find("console.serial", "denied"); !ok {
		t.Error("stale step-up not audited")
	}
	_, viewer, _ := serialHarness(t, authz.RoleViewer)
	result(viewer.get("/servers/r730xd/serial")).status(t, http.StatusForbidden).contains(t, "The serial console needs the admin role.")
	_, operator, _ := serialHarness(t, authz.RoleOperator)
	result(operator.get("/servers/r730xd/serial")).status(t, http.StatusForbidden)
	_, a2, _ := serialHarness(t, authz.RoleAdmin)
	result(a2.get("/servers/r240/serial")).status(t, http.StatusNotFound)
	result(a2.get("/servers/nope/serial")).status(t, http.StatusNotFound)

	h3 := newHarness(t) // no serial console wired
	c3 := h3.client("192.0.2.6")
	c3.login("boss", h3.addUser("boss", authz.RoleAdmin, true))
	result(c3.get("/servers/r730xd/serial")).status(t, http.StatusNotFound)
	result(c3.do(http.MethodPost, "/servers/r730xd/serial", url.Values{})).status(t, http.StatusNotFound)
	result(c3.get("/servers/r730xd")).contains(t, "<span>Serial console</span><span class=\"mi-sub\">Not configured for this server</span>")
}

func serialCSRF(t *testing.T, c *client) string {
	t.Helper()
	return csrfFor(t, c.get("/servers/r730xd/serial").Body.String(), "/servers/r730xd/serial")
}

func TestSerialStartIssuesTicketAndRendersPage(t *testing.T) {
	t.Parallel()
	_, c, fs := serialHarness(t, authz.RoleAdmin)
	rec := c.do(http.MethodPost, "/servers/r730xd/serial", url.Values{csrfField: {serialCSRF(t, c)}})
	result(rec).status(t, http.StatusOK).contains(t, `data-ticket="stk-r730xd"`, `data-ws="/servers/r730xd/serial/ws"`,
		`<script type="module" src="/static/serial.js?v=dev"></script>`, `role="toolbar" aria-label="Serial console controls"`,
		"Send break", `Send Ctrl-\ (end console)`, "Copy", `aria-label="Larger text"`, "Disconnect",
		`role="log"`, "Plain-text transcript", `id="serial-silent"`, "console=ttyS1,115200n8",
		`href="/static/vendor/xterm-6.0.0/xterm.css?v=dev"`, "SSH, legacy algorithms")
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
	g, ok := fs.lastGrant()
	if !ok || g.ServerID != "r730xd" || g.Username != "boss" || g.Takeover || g.Session == ([32]byte{}) {
		t.Errorf("grant %+v", g)
	}
	// Forged CSRF: refused and audited.
	h, c2, _ := serialHarness(t, authz.RoleAdmin)
	result(c2.do(http.MethodPost, "/servers/r730xd/serial", url.Values{csrfField: {"forged"}})).status(t, http.StatusForbidden)
	if e, ok := h.audit.find("console.serial", "denied"); !ok || e.ErrorClass != "csrf" {
		t.Errorf("csrf refusal audit %+v", e)
	}
}

func TestSerialTakeoverAndErrors(t *testing.T) {
	t.Parallel()
	h, c, fs := serialHarness(t, authz.RoleAdmin)
	since := h.clock.Now().Add(-time.Minute)
	st := fs.Status("r730xd")
	st.InUse, st.Active = true, console.Active{Username: "alice", Since: since}
	fs.setStatus("r730xd", st)
	result(c.get("/servers/r730xd")).contains(t, "In use", "<strong>alice</strong>", ">Take over</a>")
	result(c.get("/servers/r730xd/serial")).contains(t, "Take over serial console", `name="takeover" value="1"`)
	result(c.do(http.MethodPost, "/servers/r730xd/serial", url.Values{csrfField: {serialCSRF(t, c)}, "takeover": {"1"}})).
		status(t, http.StatusOK)
	if g, _ := fs.lastGrant(); !g.Takeover {
		t.Error("takeover not requested")
	}
	cases := []struct {
		err    error
		status int
		msg    string
	}{
		{&console.InUseError{Active: console.Active{Username: "alice"}}, http.StatusConflict, "in use by alice"},
		{console.ErrSerialNoLogin, http.StatusConflict, "No operator login"},
		{console.ErrSerialNoHostKey, http.StatusConflict, "ssh_host_key"},
		{console.ErrSerialUnsupported, http.StatusConflict, "not implemented"},
		{console.ErrCoolingDown, http.StatusTooManyRequests, "rejected the operator login"},
		{console.ErrSerialNotConfigured, http.StatusNotFound, "No serial console"},
		{errors.New("boom"), http.StatusServiceUnavailable, "could not be started"},
	}
	for _, tc := range cases {
		fs.issueErr = tc.err
		result(c.do(http.MethodPost, "/servers/r730xd/serial", url.Values{csrfField: {serialCSRF(t, c)}})).
			status(t, tc.status).contains(t, tc.msg).lacks(t, "data-ticket")
	}
	if e, ok := h.audit.find("console.serial", "denied"); !ok || e.ErrorClass == "" {
		t.Errorf("issue refusal audit %+v", e)
	}
}

func TestSerialCardStates(t *testing.T) {
	t.Parallel()
	v := fleetAt(time.Now())[0]
	unknown := fleetAt(time.Now())[2]
	capable := v
	f := capable.Capabilities.Flags()
	f.SerialConsole = true
	capable.Capabilities = bmc.NewCapabilities(bmc.CapabilityParams{Flags: f})
	ok := console.SerialStatus{Configured: true, Supported: true, HasLogin: true, HasHostKey: true}
	with := func(mod func(*console.SerialStatus)) console.SerialStatus {
		s := ok
		mod(&s)
		return s
	}
	cases := []struct {
		name  string
		v     ServerView
		st    console.SerialStatus
		state cardState
		msg   string
	}{
		{"unknown", unknown, console.SerialStatus{}, cardUnknown, "first full poll"},
		{"unsupported", v, console.SerialStatus{}, cardUnsupported, "does not report"},
		{"capable not set up", capable, console.SerialStatus{}, cardSetup, "not set up"},
		{"sol", v, with(func(s *console.SerialStatus) { s.Supported = false }), cardUnsupported, "Serial-over-LAN"},
		{"no login", v, with(func(s *console.SerialStatus) { s.HasLogin = false }), cardSetup, "operator login"},
		{"no host key", v, with(func(s *console.SerialStatus) { s.HasHostKey = false }), cardSetup, "ssh_host_key"},
		{"rejected", v, with(func(s *console.SerialStatus) { s.RejectedAt = time.Now() }), cardSetup, "rejected the operator login"},
		{"host key", v, with(func(s *console.SerialStatus) { s.Last.Class = "host_key" }), cardSetup, "does not match"},
		{"algorithms", v, with(func(s *console.SerialStatus) { s.Last.Class = "algorithms" }), cardSetup, "idrac8_legacy_ssh"},
		{"refused", v, with(func(s *console.SerialStatus) { s.Last.Class = "bmc_protocol" }), cardSetup, "console com2"},
		{"unreachable", v, with(func(s *console.SerialStatus) { s.Last.Class = "timeout" }), cardReady, "Screen-reader"},
		{"ready", v, ok, cardReady, "BIOS"},
	}
	for _, tc := range cases {
		c := buildSerialCard(tc.v, tc.st, fmtIn(time.UTC))
		if c.State != tc.state || !strings.Contains(c.Message, tc.msg) {
			t.Errorf("%s: state %s msg %q", tc.name, c.State, c.Message)
		}
		if (c.State == cardReady) != c.Open {
			t.Errorf("%s: Open = %v", tc.name, c.Open)
		}
	}
	if c := buildSerialCard(v, with(func(s *console.SerialStatus) { s.Last.Class = "unreachable" }), fmtIn(time.UTC)); len(c.Warnings) != 2 {
		t.Errorf("unreachable warnings %v", c.Warnings)
	}
}

func TestSerialWebSocket(t *testing.T) {
	t.Parallel()
	h, c, fs := serialHarness(t, authz.RoleAdmin)
	srv := httptest.NewServer(h.handler)
	t.Cleanup(srv.Close)
	cookie := c.jar[auth.SessionCookieName]
	conn, code, err := serialDial(t, srv, "/servers/r730xd/serial/ws?ticket=stk-r730xd", cookie, srv.URL)
	if err != nil {
		t.Fatalf("dial: %v (%d)", err, code)
	}
	if conn.Subprotocol() != serialSubprotocol {
		t.Errorf("subprotocol %q", conn.Subprotocol())
	}
	ctx := context.Background()
	if typ, b, rerr := conn.Read(ctx); rerr != nil || typ != websocket.MessageText || string(b) != `{"type":"connected"}` {
		t.Fatalf("status %v %q %v", typ, b, rerr)
	}
	if typ, b, rerr := conn.Read(ctx); rerr != nil || typ != websocket.MessageBinary || string(b) != "login: " {
		t.Fatalf("output %v %q %v", typ, b, rerr)
	}
	_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"break"}`))
	if typ, b, rerr := conn.Read(ctx); rerr != nil || typ != websocket.MessageText || string(b) != `{"type":"break"}` {
		t.Fatalf("echo %v %q %v", typ, b, rerr)
	}
	waitCond(t, func() bool { return len(fs.calls()) == 1 })
	call := fs.calls()[0]
	if call.ticket != "stk-r730xd" || call.server != "r730xd" || call.session != console.SessionHash(cookie) {
		t.Errorf("ServeSerial called with %+v", call)
	}
	if err = call.check(ctx); err != nil {
		t.Errorf("watchdog on a live session: %v", err)
	}
	_ = h.authn.Logout(ctx, cookie)
	if err = call.check(ctx); !errors.Is(err, console.ErrSessionEnded) {
		t.Errorf("after logout: %v", err)
	}
	_ = conn.CloseNow()
}

func serialDial(t *testing.T, srv *httptest.Server, path, cookie, origin string) (*websocket.Conn, int, error) {
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
		&websocket.DialOptions{HTTPHeader: hdr, Subprotocols: []string{serialSubprotocol}})
	code := 0
	if resp != nil {
		code = resp.StatusCode
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}
	return c, code, err
}

func TestSerialWebSocketRefusals(t *testing.T) {
	t.Parallel()
	h, c, fs := serialHarness(t, authz.RoleAdmin)
	srv := httptest.NewServer(h.handler)
	t.Cleanup(srv.Close)
	cookie := c.jar[auth.SessionCookieName]
	cases := map[string]struct {
		path, cookie, origin string
		want                 int
	}{
		"no cookie":      {"/servers/r730xd/serial/ws?ticket=t", "", "", http.StatusUnauthorized},
		"bad cookie":     {"/servers/r730xd/serial/ws?ticket=t", "garbage", "", http.StatusUnauthorized},
		"no ticket":      {"/servers/r730xd/serial/ws", cookie, "", http.StatusNotFound},
		"long ticket":    {"/servers/r730xd/serial/ws?ticket=" + strings.Repeat("a", 65), cookie, "", http.StatusNotFound},
		"bad server id":  {"/servers/R!/serial/ws?ticket=t", cookie, "", http.StatusNotFound},
		"foreign origin": {"/servers/r730xd/serial/ws?ticket=t", cookie, "https://evil.example", http.StatusForbidden},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, code, err := serialDial(t, srv, tc.path, tc.cookie, tc.origin); err == nil || code != tc.want {
				t.Fatalf("code %d err %v, want %d", code, err, tc.want)
			}
		})
	}
	h.clock.Advance(6 * time.Minute)
	if _, code, err := serialDial(t, srv, "/servers/r730xd/serial/ws?ticket=t", cookie, ""); err == nil || code != http.StatusForbidden {
		t.Fatalf("stale step-up: %d %v", code, err)
	}
	if len(fs.calls()) != 0 {
		t.Error("a refused upgrade reached the broker")
	}
	// A broker refusal (bad ticket) closes the socket.
	h2, c2, fs2 := serialHarness(t, authz.RoleAdmin)
	fs2.serveErr = console.ErrTicketInvalid
	srv2 := httptest.NewServer(h2.handler)
	t.Cleanup(srv2.Close)
	conn, _, err := serialDial(t, srv2, "/servers/r730xd/serial/ws?ticket=t", c2.jar[auth.SessionCookieName], "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = conn.Read(context.Background()); websocket.CloseStatus(err) != websocket.StatusNormalClosure {
		t.Errorf("after a refused ticket: %v", err)
	}
}

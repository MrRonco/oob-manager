package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"oob-manager/internal/auth"
	"oob-manager/internal/bmc"
	"oob-manager/internal/config"
	"oob-manager/internal/secrets"
	"oob-manager/internal/store"
	"oob-manager/internal/store/authrepo"
)

// testGELFAddr is the GELF address the test config names (TEST-NET-1, inside its
// allowed_networks); gelfDialTo sends it to a local receiver.
const testGELFAddr = "192.0.2.30:12201"

// gelfDialTo dials local instead of the configured TEST-NET address.
func gelfDialTo(local string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != testGELFAddr {
			return nil, errors.New("test: unexpected GELF dial to " + addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, local)
	}
}

// gelfSink accepts GELF TCP connections and discards what they send.
func gelfSink(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c); _ = c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func testClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed test cert
	}}
}

func get(t *testing.T, c *http.Client, url, token string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

// issueToken creates a user and a read-only token through a second connection to the
// running app's database (SQLite WAL allows it).
func issueToken(t *testing.T, dbPath string) string {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Users().Create(ctx, store.User{ID: "u1", Username: "morgan", Role: store.RoleAdmin,
		PwHash: "x", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	ts, err := auth.NewTokenService(authrepo.New(db).Tokens, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := ts.Issue(ctx, "test", "u1")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestServeEndToEnd(t *testing.T) {
	sink := gelfSink(t)
	d := newDeployment(t, testGELFAddr)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, errOut syncBuffer
	e := cliEnv(ctx, strings.NewReader(""), &out, &errOut)
	var listens atomic.Int32
	e.listen = func(string, string) (net.Listener, error) { listens.Add(1); return ln, nil }
	e.newDriver = d.mockDrivers(t)
	e.gelfDial = gelfDialTo(sink)
	done := make(chan int, 1)
	go func() { done <- run([]string{"oob-manager", "serve", "-config", d.configPath}, e) }()

	base, c := "https://"+ln.Addr().String(), testClient()
	defer func() {
		if n := listens.Load(); n != 1 {
			t.Errorf("serve opened %d listeners; want exactly the TLS one", n)
		}
	}()
	waitUntil(t, "readyz ok", func() bool {
		code, _, body := get(t, c, base+"/readyz", "")
		return code == 200 && strings.Contains(body, `"ok"`)
	})
	if code, _, body := get(t, c, base+"/healthz", ""); code != 200 || !strings.Contains(body, "ok") {
		t.Fatalf("healthz %d %s", code, body)
	}
	// Plain HTTP on the same port is refused, not redirected.
	plain := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	if code, hdr, _ := get(t, plain, "http://"+ln.Addr().String()+"/healthz", ""); code != http.StatusBadRequest ||
		hdr.Get("Location") != "" {
		t.Fatalf("plain HTTP: %d %v", code, hdr)
	}
	code, hdr, body := get(t, c, base+"/", "")
	// The client follows the redirect from / to the login page.
	if code != http.StatusOK || hdr.Get("Content-Security-Policy") == "" ||
		!strings.Contains(body, `action="/login"`) {
		t.Fatalf("UI login %d %v %s", code, hdr, body)
	}
	if unauth, _, _ := get(t, c, base+"/api/v1/servers", ""); unauth != http.StatusUnauthorized {
		t.Fatalf("API without token: %d", unauth)
	}
	token := issueToken(t, d.dbPath)
	code, _, body = get(t, c, base+"/api/v1/servers", token)
	var list struct {
		Data []struct {
			ID        string `json:"id"`
			Reachable bool   `json:"reachable"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &list); code != 200 || err != nil || len(list.Data) != 1 ||
		list.Data[0].ID != "r240" || !list.Data[0].Reachable {
		t.Fatalf("servers %d %s", code, body)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exit %d: %s", code, errOut.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not shut down")
	}
	assertAudited(t, d.dbPath, "app.start", "app.stop")
	if strings.Contains(errOut.String(), "fixture-only-password") {
		t.Fatal("a BMC password reached the log")
	}
}

func assertAudited(t *testing.T, dbPath string, actions ...string) {
	t.Helper()
	db, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Audit().List(context.Background(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range rows {
		seen[r.Action] = true
	}
	for _, a := range actions {
		if !seen[a] {
			t.Errorf("audit row %q missing (have %v)", a, seen)
		}
	}
}

func TestServeStartupFailures(t *testing.T) {
	d := newDeployment(t, "")
	var out, errOut syncBuffer
	e := cliEnv(context.Background(), strings.NewReader(""), &out, &errOut)
	if code := run([]string{"oob-manager", "serve", "-config", d.dir + "/missing.yaml"}, e); code != 1 {
		t.Fatalf("missing config: %d", code)
	}
	if code := run([]string{"oob-manager", "serve", "-config", d.configPath, "extra"}, e); code != 1 {
		t.Fatalf("extra args: %d", code)
	}
	// The real driver factory is used; the listener fails, so nothing is contacted.
	e.listen = func(string, string) (net.Listener, error) { return nil, net.ErrClosed }
	if code := run([]string{"oob-manager", "serve", "-config", d.configPath}, e); code != 1 {
		t.Fatalf("listen failure: %d", code)
	}
	write(t, d.dir+"/tls.key", []byte("not a key"))
	if code := run([]string{"oob-manager", "serve", "-config", d.configPath}, e); code != 1 ||
		!strings.Contains(errOut.String(), "tls") {
		t.Fatalf("bad TLS key: %d %s", code, errOut.String())
	}
	write(t, d.dir+"/app-keys.age", []byte("garbage"))
	if code := run([]string{"oob-manager", "serve", "-config", d.configPath}, e); code != 1 {
		t.Fatalf("bad app keys: %d", code)
	}
}

func TestServeRefusesToStartWithoutTLSFiles(t *testing.T) {
	for _, missing := range []string{"tls.crt", "tls.key"} {
		d := newDeployment(t, "")
		if err := os.Remove(filepath.Join(d.dir, missing)); err != nil {
			t.Fatal(err)
		}
		var out, errOut syncBuffer
		e := cliEnv(context.Background(), strings.NewReader(""), &out, &errOut)
		listened := false
		e.listen = func(string, string) (net.Listener, error) { listened = true; return nil, net.ErrClosed }
		e.newDriver = func(config.Server, secrets.Credential) (bmc.Driver, error) {
			t.Error("a driver was built before TLS was checked")
			return nil, errNoDriver
		}
		if code := run([]string{"oob-manager", "serve", "-config", d.configPath}, e); code != 1 ||
			!strings.Contains(errOut.String(), "gen-tls") {
			t.Fatalf("missing %s: %d %s", missing, code, errOut.String())
		}
		if _, err := os.Stat(d.dbPath); !os.IsNotExist(err) || listened {
			t.Fatalf("missing %s: db created (%v) or listener opened (%v)", missing, err, listened)
		}
	}
}

func TestTrustedOrigins(t *testing.T) {
	if got := trustedOrigins("https://oob.example.test:8443/path"); len(got) != 1 || got[0] != "https://oob.example.test:8443" {
		t.Fatalf("got %v", got)
	}
	if got := trustedOrigins("::"); got != nil {
		t.Fatalf("got %v", got)
	}
}

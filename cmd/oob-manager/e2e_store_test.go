//go:build e2e

package main

// A store-style install (docs/plans/09-store-ready-install.md): an empty data directory
// and no config.yaml, no mounted secrets, no certificate. The real `serve` must generate
// its certificate and keys, print a setup code, and let the administrator create the first admin
// in the browser, sign in and acknowledge the key backup.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const storeAdmin, storePassword = "owner", "store install password, not a secret"

var (
	setupCodeRe = regexp.MustCompile(`setup code ([A-Z2-7]{4}(?:-[A-Z2-7]{4}){7})`)
	secretRe    = regexp.MustCompile(`data-secret="([A-Z2-7]+)"`)
)

func TestE2EStoreInstall(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	e := cliEnv(ctx, strings.NewReader(""), &syncBuffer{}, logs)
	e.listen = func(string, string) (net.Listener, error) { return ln, nil }
	e.paths = pathDefaults{config: filepath.Join(dir, "etc", "oob-manager", "config.yaml"),
		legacyConfig: filepath.Join(dir, "etc", "oob-console", "config.yaml"),
		db:           filepath.Join(data, "oob-manager.db"), legacyDB: filepath.Join(data, "oob-console.db"),
		identity: filepath.Join(dir, "run", "age-identity"), appKeys: filepath.Join(dir, "run", "app-keys.age"),
		creds: filepath.Join(dir, "run", "bmc-credentials.age")}
	done := make(chan int, 1)
	go func() { done <- run([]string{"oob-manager", "serve"}, e) }()
	stopped := false
	stop := func() int {
		if stopped {
			return 0
		}
		stopped = true
		cancel()
		select {
		case code := <-done:
			return code
		case <-time.After(15 * time.Second):
			return -1
		}
	}
	t.Cleanup(func() { stop() })

	var code string
	waitFor(t, "the setup code in the log", func() bool {
		m := setupCodeRe.FindStringSubmatch(logs.String())
		if m != nil {
			code = m[1]
		}
		return m != nil
	})
	checkGeneratedFiles(t, data)
	b := browser{t: t, base: "https://" + ln.Addr().String(), c: trustingClient(t, filepath.Join(data, "tls", "tls.crt"))}

	expectRedirect(t, b.get("/"), "/login")
	expectPage(t, b.get("/login"), `href="/setup"`)
	if p := b.submit("/setup", "/setup", url.Values{"code": {"AAAA-BBBB"}, "username": {storeAdmin},
		"password": {storePassword}, "confirm": {storePassword}}); p.status != http.StatusUnauthorized {
		t.Fatalf("wrong setup code: %d", p.status)
	}
	reveal := b.submit("/setup", "/setup", url.Values{"code": {code}, "username": {storeAdmin},
		"password": {storePassword}, "confirm": {storePassword}})
	expectPage(t, reveal, "Scan your authenticator")
	m := secretRe.FindStringSubmatch(reveal.body)
	if m == nil {
		t.Fatal("no authenticator secret on the reveal page")
	}
	secret := m[1]
	if p := b.get("/setup"); p.status != http.StatusNotFound {
		t.Fatalf("/setup after the admin exists: %d", p.status)
	}
	enrolled := b.post("/enroll", url.Values{"username": {storeAdmin}, "password": {storePassword},
		"code": {totpCode(t, secret, time.Now())}, "csrf_token": {csrfFrom(t, b.get("/enroll"))}})
	expectPage(t, enrolled, "Sign in")

	form := url.Values{"username": {storeAdmin}, "password": {storePassword}, "csrf_token": {csrfFrom(t, b.get("/login"))}}
	expectRedirect(t, b.post("/login", form), "/login/totp")
	totp := url.Values{"code": {totpCode(t, secret, time.Now().Add(30*time.Second))},
		"csrf_token": {csrfFrom(t, b.get("/login/totp"))}}
	expectRedirect(t, b.post("/login/totp", totp), "/")
	overview := b.get("/")
	expectPage(t, overview, "Back up the encryption key", filepath.Join(data, "keys", "age-identity"))
	expectRedirect(t, b.submit("/", "/keys/backup-notice", url.Values{"next": {"/"}}), "/")
	if p := b.get("/"); strings.Contains(p.body, "Back up the encryption key") {
		t.Fatal("backup notice still shown after acknowledging it")
	}
	if _, err := os.Stat(filepath.Join(data, "keys", "BACKUP-PENDING")); !os.IsNotExist(err) {
		t.Fatal("backup marker still on disk")
	}
	if exit := stop(); exit != 0 {
		t.Fatalf("serve exited %d:\n%s", exit, logs.String())
	}
	if strings.Count(logs.String(), code) != 1 {
		t.Error("the setup code was logged more than once")
	}
	restartStoreInstall(t, e, data)
}

// restartStoreInstall checks the review fix M1 end to end: the marked store install
// starts again without config.yaml (accounts now exist) and logs no new setup code; the
// same data without the marker (a configured install that lost its config.yaml) is
// refused, and the refused start leaves the database alone.
func restartStoreInstall(t *testing.T, e env, data string) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	e2 := cliEnv(ctx, strings.NewReader(""), &syncBuffer{}, logs)
	e2.listen = func(string, string) (net.Listener, error) { return ln, nil }
	e2.paths = e.paths
	done := make(chan int, 1)
	go func() { done <- run([]string{"oob-manager", "serve"}, e2) }()
	b := browser{t: t, base: "https://" + ln.Addr().String(), c: trustingClient(t, filepath.Join(data, "tls", "tls.crt"))}
	waitFor(t, "the restarted store install", func() bool {
		req, rerr := http.NewRequestWithContext(context.Background(), http.MethodGet, b.base+"/readyz", nil)
		if rerr != nil {
			return false
		}
		resp, gerr := b.c.Do(req)
		if gerr != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	if setupCodeRe.MatchString(logs.String()) {
		t.Error("a restart with an account logged a setup code")
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("restarted serve exited %d:\n%s", code, logs.String())
	}

	if err = os.Remove(filepath.Join(data, storeMarkerName)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(data, "oob-manager.db")) //nolint:gosec // G304: the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	refused := &syncBuffer{}
	e3 := cliEnv(context.Background(), strings.NewReader(""), &syncBuffer{}, refused)
	e3.paths = e.paths
	if code := run([]string{"oob-manager", "serve"}, e3); code == 0 ||
		!strings.Contains(refused.String(), "refusing to start on built-in defaults") {
		t.Fatalf("an unmarked data volume with accounts started without config.yaml (exit %d):\n%s", code, refused.String())
	}
	after, err := os.ReadFile(filepath.Join(data, "oob-manager.db")) //nolint:gosec // G304: the test's temp dir
	if err != nil || string(before) != string(after) {
		t.Fatal("a refused start changed the database")
	}
}

func checkGeneratedFiles(t *testing.T, data string) {
	t.Helper()
	for path, want := range map[string]os.FileMode{
		filepath.Join(data, "keys"):                 0o700 | os.ModeDir,
		filepath.Join(data, "keys", "age-identity"): 0o400,
		filepath.Join(data, "keys", "app-keys.age"): 0o400,
		filepath.Join(data, "tls", "tls.key"):       0o400,
	} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if got := fi.Mode() & (os.ModePerm | os.ModeDir); got != want {
			t.Errorf("%s mode %v, want %v", path, got, want)
		}
	}
}

func trustingClient(t *testing.T, certPath string) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(certPath) //nolint:gosec // G304: the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("bad generated certificate")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Timeout: 10 * time.Second, Jar: jar,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

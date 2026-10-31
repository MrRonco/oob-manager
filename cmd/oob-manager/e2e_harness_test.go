//go:build e2e

package main

// End-to-end harness: two Redfish mock BMCs (iDRAC8 R730XD and iDRAC9 R240 fixtures)
// over TLS, a generated install (config with the mocks' SPKI pins, age identity,
// encrypted BMC credentials and app keys, TLS pair, SQLite DB), an admin bootstrapped
// through the real `bootstrap-admin` command, and the real `serve` command running
// in-process. Nothing here contacts a real BMC: the configured addresses are from
// 192.0.2.0/24 (TEST-NET-1) and the driver endpoint is replaced by the mock's URL.

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/bmcssh/sshtest"
	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/config"
	"oob-manager/internal/console/rfbtest"
	"oob-manager/internal/secrets"
)

// Test-only identities. The password exists only in this file and in temp dirs.
const (
	e2eUser     = "admin"
	e2ePassword = "e2e test password, not a secret"
)

// e2eServer is one mock BMC and the config entry that points at it.
type e2eServer struct {
	id, name, address, kind, fixture string
}

func e2eServers() []e2eServer {
	return []e2eServer{
		{"r730xd", "Storage node R730XD", "192.0.2.10", "idrac8", "idrac8-r730xd"},
		{"r240", "Edge node R240", "192.0.2.11", "idrac9", "idrac9-r240"},
	}
}

// stack is a running app plus everything needed to drive it.
type stack struct {
	catalog    *catalogSrv // the vendor catalog server (e2e_catalog_harness_test.go)
	base       string
	dir        string
	configPath string
	dbPath     string
	certPath   string
	secret     string       // admin TOTP secret
	token      string       // read-only API token
	uiToken    string       // token minted in the Settings UI (checkSettings)
	newSecret  string       // TOTP secret of the user enrolled by link (checkSettings)
	viewer     *http.Client // that user's signed-in browser (checkSettings), reused by checkGeneral
	mocks      map[string]*redfishmock.Server
	vnc        *rfbtest.Server            // the R730XD's VNC server (TLS)
	ssh        map[string]*sshtest.Server // each server's BMC SSH serial console
	plain      *plainHTTP                 // every BMC's plain-HTTP port (e2e_security_harness_test.go)
	errOut     *syncBuffer
	stop       func() int
	extraYAML  string    // top-level config keys added before servers: (startStackWith)
	hooks      *hookRecv // the file-managed webhook notification target (e2e_notify_test.go)
	// gelfPlain and gelfTLS are the GELF inputs Settings → Integrations can ship to
	// (e2e_gelf_harness_test.go).
	gelfPlain, gelfTLS *gelfInput
	// seedEnd is the grid line the history seed ends on; the UI draws its charts for it.
	seedEnd time.Time
	// stepUp is the env.stepUpWindow test hook (0: the configured window).
	stepUp time.Duration
	// extra is the BMC added in the browser by checkServers (slice S3): not in
	// config.yaml, reachable only at extraAddress.
	extra    *redfishmock.Server
	extraSSH *sshtest.Server
	// probeDials counts the security checks' dials per address (dialProbe): the console
	// reaches the same fake VNC server, so the server's own count cannot tell them apart.
	probeDials dialCounter
	// showcase: the README screenshot fakes (e2e_showcase_harness_test.go).
	showcase bool
}

// The browser-added BMC (checkServers).
const (
	extraID      = "r650"
	extraAddress = "192.0.2.12"
)

// mockFor is the mock BMC of a server id: a config.yaml server's own mock, else the
// one BMC that can be added in the browser (whatever id it is given).
func (s *stack) mockFor(id string) *redfishmock.Server {
	if m, ok := s.mocks[id]; ok {
		return m
	}
	return s.extra
}

// dialBMC sends fingerprint fetches for the browser-added BMC to its fakes; anything
// else is refused, so no real network is ever dialled.
func (s *stack) dialBMC(ctx context.Context, network, addr string) (net.Conn, error) {
	switch addr {
	case extraAddress + ":443":
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(s.extra.URL(), "https://"))
	case extraAddress + ":22":
		return (&net.Dialer{}).DialContext(ctx, network, s.extraSSH.Addr())
	}
	return nil, errors.New("e2e: unexpected BMC dial to " + addr)
}

// startStack builds the install and starts `serve` on listenAddr ("127.0.0.1:0" for a
// random port). The returned stack is shut down by t.Cleanup.
func startStack(t *testing.T, listenAddr string) *stack {
	t.Helper()
	return startStackWith(t, listenAddr, "")
}

// startStackStepUp is startStack with a step-up window of a few seconds, set through
// the env test hook: config.yaml only accepts 1–5 minutes.
func startStackStepUp(t *testing.T, listenAddr string, window time.Duration) *stack {
	t.Helper()
	return startStackOpts(t, listenAddr, "", window)
}

// startStackWith is startStack with extra top-level config.
func startStackWith(t *testing.T, listenAddr, extraYAML string) *stack {
	t.Helper()
	return startStackOpts(t, listenAddr, extraYAML, 0)
}

func startStackOpts(t *testing.T, listenAddr, extraYAML string, stepUp time.Duration) *stack {
	t.Helper()
	return startStackMode(t, listenAddr, extraYAML, stepUp, false)
}

// startStackMode is startStackOpts, with the README screenshot fakes when showcase is set
// (the dev server with OOB_DEV_SHOWCASE=1 only, e2e_showcase_harness_test.go).
func startStackMode(t *testing.T, listenAddr, extraYAML string, stepUp time.Duration, showcase bool) *stack {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	s := &stack{dir: t.TempDir(), mocks: map[string]*redfishmock.Server{}, errOut: &syncBuffer{}, extraYAML: extraYAML,
		stepUp: stepUp, showcase: showcase}
	s.base = "https://" + ln.Addr().String()
	showcaseOpts := showcaseMockOptions(t, showcase)
	for _, srv := range e2eServers() {
		// The SYNTHETIC firmware member documents name every component (tech_doc §38).
		opts := append(mockOptions(srv.id), redfishmock.WithExtraFixtures(
			redfishmock.FixtureDir(t, filepath.Join("synthetic-firmware", srv.fixture))))
		s.mocks[srv.id] = redfishmock.New(t, redfishmock.FixtureDir(t, srv.fixture), append(opts, showcaseOpts...)...)
	}
	s.extra = redfishmock.New(t, redfishmock.FixtureDir(t, "idrac9-r240"),
		append([]redfishmock.Option{redfishmock.WithPowerControl(e2ePowerTransition)}, showcaseOpts...)...)
	s.extraSSH = sshtest.New(t, sshtest.Options{User: redfishmock.OperatorUser, Password: redfishmock.OperatorPassword})
	s.vnc = rfbtest.New(t, vncOptions(t, showcase))
	s.ssh = startSSH(t, showcase)
	s.plain = newPlainHTTP(t)
	s.hooks = newHookRecv(t)
	s.gelfPlain, s.gelfTLS = newGELFInput(t, false), newGELFInput(t, true)
	s.catalog = newCatalogSrv(t, s.dir)
	s.extraYAML = withCatalog(s.extraYAML, s.catalog.yaml(s.dir))
	s.writeInstall(t, ln.Addr().String())
	s.importSeedCatalog(t)
	s.secret = s.bootstrapAdmin(t)
	s.token = s.issueReadOnlyToken(t)
	s.seedHistory(t) // 48 h of samples before serve (e2e_history_test.go)
	s.serve(t, ln)
	return s
}

func (s *stack) writeInstall(t *testing.T, addr string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(s.dir, "identity"), []byte(id.String()+"\n"))
	var creds strings.Builder
	for _, srv := range e2eServers() {
		creds.WriteString(srv.id + "-ro: {username: " + redfishmock.User + ", password: " + redfishmock.Password + "}\n")
		creds.WriteString(srv.id + "-op: {username: " + redfishmock.OperatorUser + ", password: " + redfishmock.OperatorPassword + "}\n")
	}
	creds.WriteString("r730xd-vnc: {password: \"" + rfbtest.Password + "\"}\n")
	creds.WriteString("notify-hook: {password: " + e2eHookSecret + "}\n")
	write(t, filepath.Join(s.dir, "creds.age"), seal(t, id.Recipient(), creds.String()))
	write(t, filepath.Join(s.dir, "app-keys.age"), seal(t, id.Recipient(), genAppKeys(t)))
	writeCert(t, s.dir)
	s.configPath = filepath.Join(s.dir, "config.yaml")
	s.dbPath = filepath.Join(s.dir, "oob.db")
	s.certPath = filepath.Join(s.dir, "tls.crt")
	write(t, s.configPath, []byte(s.configYAML(addr)))
}

// genAppKeys runs the real `gen-app-keys` command and returns its stdout.
func genAppKeys(t *testing.T) string {
	t.Helper()
	var out, errOut syncBuffer
	if code := run([]string{"oob-manager", "gen-app-keys"}, cliEnv(context.Background(), strings.NewReader(""), &out, &errOut)); code != 0 {
		t.Fatalf("gen-app-keys: %d %s", code, errOut.String())
	}
	return out.String()
}

func (s *stack) configYAML(addr string) string {
	var b strings.Builder
	b.WriteString(`listen: "` + addr + `"
tls: { cert_file: ` + s.dir + `/tls.crt, key_file: ` + s.dir + `/tls.key }
public_url: https://` + addr + `/
ratelimit: { login_acct_per_hour: 20 } # every Playwright spec signs the admin in
storage: { db_path: ` + s.dir + `/oob.db, lease_dir: ` + s.dir + ` }
secrets:
  credentials_file: ` + s.dir + `/creds.age
  identity_file: ` + s.dir + `/identity
  app_keys_file: ` + s.dir + `/app-keys.age
settings: { bmc_networks: [192.0.2.0/24] }
` + gelfYAML + s.extraYAML + s.notifyYAML() + `servers:
`)
	for _, srv := range e2eServers() {
		b.WriteString(`  - id: ` + srv.id + `
    name: ` + srv.name + `
    bmc: { address: ` + srv.address + `, kind: ` + srv.kind + ` }
    tls_pin_sha256: "` + s.mocks[srv.id].PinSHA256() + `"
` + s.consoleYAML(srv.id) + s.powerYAML(srv.id))
	}
	return b.String()
}

// bootstrapAdmin drives the real `bootstrap-admin` command: password twice, then a
// code computed from the printed secret. The code is for the previous 30 s step, so
// a login code for the current step is accepted right away (codes are single-use).
//
// The command checks the password (argon2id, slow under -race) before the code, so a
// 30 s boundary can pass in between and put the code outside the ±1 step window. The
// command then asks again (confirmAttempts): a refused code is answered with a fresh
// one, and the wait is bounded, so a refusal fails the test with the command's output
// instead of hanging the whole run (seen as a 10 minute timeout in TestE2E/servers).
func (s *stack) bootstrapAdmin(t *testing.T) string {
	t.Helper()
	pr, pw := io.Pipe()
	out := &syncBuffer{}
	e := cliEnv(context.Background(), strings.NewReader(""), out, s.errOut)
	e.in = bufio.NewReader(pr)
	done := make(chan int, 1)
	go func() {
		done <- run([]string{"oob-manager", "bootstrap-admin", "-config", s.configPath, "-username", e2eUser}, e)
	}()
	writeLine(t, pw, e2ePassword+"\n"+e2ePassword)
	var secret string
	waitFor(t, "bootstrap secret", func() bool {
		m := secretLine.FindStringSubmatch(out.String())
		if m != nil {
			secret = m[1]
		}
		return m != nil
	})
	for attempt := 1; ; attempt++ {
		refused := strings.Count(s.errOut.String(), bootstrapRefusal)
		writeLine(t, pw, totpCode(t, secret, time.Now().Add(-30*time.Second)))
		code, exited := s.waitBootstrap(t, done, refused)
		if exited {
			if code != 0 {
				t.Fatalf("bootstrap-admin exit %d: %s", code, s.errOut.String())
			}
			break
		}
		if attempt == confirmAttempts {
			t.Fatalf("bootstrap-admin refused %d codes: %s", attempt, s.errOut.String())
		}
	}
	_ = pw.Close()
	if !strings.Contains(out.String(), "TOTP confirmed") {
		t.Fatalf("bootstrap output: %s", out.String())
	}
	return secret
}

// bootstrapRefusal is what bootstrap-admin prints when a code is not accepted.
const bootstrapRefusal = "That code was not accepted."

// waitBootstrap waits for the command to exit (exited true, with its code) or to refuse
// the code just written (one more refusal than seen before), within a bounded time.
func (s *stack) waitBootstrap(t *testing.T, done <-chan int, seen int) (int, bool) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		select {
		case code := <-done:
			return code, true
		default:
		}
		if strings.Count(s.errOut.String(), bootstrapRefusal) > seen {
			return 0, false
		}
		if time.Now().After(deadline) {
			t.Fatalf("bootstrap-admin did not finish: %s", s.errOut.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func writeLine(t *testing.T, w io.Writer, line string) {
	t.Helper()
	go func() { _, _ = io.WriteString(w, line+"\n") }()
}

// issueReadOnlyToken mints an API token through the real `token create` command
// (tokens are view-only by design). Only the token is on stdout.
func (s *stack) issueReadOnlyToken(t *testing.T) string {
	t.Helper()
	return s.cli(t, "token", "create", "-config", s.configPath, "-name", "e2e", "-expires", "1d")
}

// cli runs one subcommand in-process and returns its trimmed stdout; it fails the test
// on a non-zero exit.
func (s *stack) cli(t *testing.T, args ...string) string {
	t.Helper()
	var out syncBuffer
	e := cliEnv(context.Background(), strings.NewReader(""), &out, s.errOut)
	if code := run(append([]string{"oob-manager"}, args...), e); code != 0 {
		t.Fatalf("%v: exit %d: %s", args, code, s.errOut.String())
	}
	return strings.TrimSpace(out.String())
}

func (s *stack) serve(t *testing.T, ln net.Listener) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	e := cliEnv(ctx, strings.NewReader(""), &syncBuffer{}, s.errOut)
	e.listen = func(string, string) (net.Listener, error) { return ln, nil }
	e.newDriver = func(cs config.Server, ro secrets.Credential) (bmc.Driver, error) {
		return bmcDriverAt(cs, ro, s.mockFor(cs.ID).URL())
	}
	e.bmcDial = s.dialBMC
	e.gelfDial = s.dialGELF
	e.probeDial = s.dialProbe
	e.vncDial = s.dialVNC
	e.sshDial = s.dialSSH
	e.kvmEndpoint = func(cs config.Server) string { return s.mockFor(cs.ID).URL() }
	e.stepUpWindow = s.stepUp
	end := s.seedEnd
	e.uiHistoryNow = func() time.Time { return end } // the seed's grid line (e2e_history_test.go)
	e.autoRefresh = devRefresh()
	e.restart = e2eRestartCadence // a mock BMC restart is watched in seconds (e2e_bmcreset_test.go)
	e.catalogTLS, e.catalogTick = s.catalog.tls(), catalogTick
	e.catalogFirst = func() time.Duration { return time.Second }
	done := make(chan int, 1)
	go func() { done <- run([]string{"oob-manager", "serve", "-config", s.configPath}, e) }()
	var exit int
	stopped := false
	s.stop = func() int {
		if !stopped {
			stopped = true
			cancel()
			select {
			case exit = <-done:
			case <-time.After(15 * time.Second):
				exit = -1
			}
		}
		return exit
	}
	t.Cleanup(func() { s.stop() })
	c := s.client(t)
	waitFor(t, "every server polled", func() bool { return s.allPolled(c) })
}

// allPolled is true once /api/v1/servers reports every server reachable and the
// overview can show real values (SEL and inventory are read in the first cycle).
func (s *stack) allPolled(c *http.Client) bool {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.base+"/api/v1/servers", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode == http.StatusOK && strings.Count(string(b), `"reachable":true`) == len(e2eServers())
}

// client trusts the generated certificate only, keeps cookies and does not follow
// redirects, so every 303 can be asserted.
func (s *stack) client(t *testing.T) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(s.certPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("bad test certificate")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Timeout: 10 * time.Second, Jar: jar,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// devRefresh is OOB_DEV_REFRESH (the dev server's auto-refresh interval, e.g. "3s"),
// zero when unset or invalid: the Playwright refresh test needs a reload it can watch.
func devRefresh() time.Duration {
	d, err := time.ParseDuration(os.Getenv("OOB_DEV_REFRESH"))
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

func totpCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// clearOfStepEdge waits until at least margin remains in the current 30 s TOTP step, so
// a code generated now for a neighbouring step is still that neighbour when the server
// checks it (a slow runner can otherwise cross the boundary in between).
func clearOfStepEdge(margin time.Duration) {
	const step = 30 * time.Second
	if left := step - time.Duration(time.Now().UnixNano())%step; left < margin {
		time.Sleep(left + 100*time.Millisecond)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

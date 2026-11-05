package ui

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/config"
	"oob-manager/internal/registry"
	"oob-manager/internal/secrets/credstore"
	"oob-manager/internal/store"
	"oob-manager/internal/tofu"
	"oob-manager/internal/web"
)

const (
	spkiA       = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	spkiB       = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	hostKeyLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	roSecret    = "ui-test-readonly-password"
)

const serversYAML = `tls: { cert_file: /c, key_file: /k }
public_url: https://oob.test
settings: { bmc_networks: [192.0.2.0/24] }
servers:
  - id: r730xd
    name: Storage node R730XD
    bmc: { address: 192.0.2.70, kind: idrac8 }
    tls_pin_sha256: "` + spkiA + `"
    credentials: { readonly: r-ro }
`

// fakeProber records what was dialled; fetches return fixed answers.
type fakeProber struct {
	mu      sync.Mutex
	fetched []netip.AddrPort
	tests   []string
	fail    error
	last    map[string]ServerTest
}

func (p *fakeProber) FetchTLS(_ context.Context, ap netip.AddrPort, _ bool) (tofu.CertInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fetched = append(p.fetched, ap)
	if p.fail != nil {
		return tofu.CertInfo{}, p.fail
	}
	return tofu.CertInfo{SPKI: spkiB, Subject: "CN=<idrac>&co", Issuer: "CN=self", NotBefore: time.Unix(0, 0),
		NotAfter: time.Unix(4e9, 0), SANs: []string{"192.0.2.12"}}, nil
}

func (p *fakeProber) FetchSSH(_ context.Context, ap netip.AddrPort, _ bool) (tofu.HostKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fetched = append(p.fetched, ap)
	return tofu.HostKey{Line: hostKeyLine, Type: "ssh-ed25519", Fingerprint: "SHA256:abc"}, nil
}

func (p *fakeProber) StartTest(id, by string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tests = append(p.tests, id)
	p.last[id] = ServerTest{By: by, OK: true, FinishedAt: time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC),
		Kind: config.KindIDRAC9, Steps: []TestStep{{Name: "Redfish", OK: true, Detail: "Integrated Remote Access Controller."}}}
	return nil
}

func (p *fakeProber) LastTest(id string) (ServerTest, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, ok := p.last[id]
	return t, ok
}

func (p *fakeProber) fetches() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.fetched)
}

type serversEnv struct {
	*settingsEnv
	reg    *registry.Service
	prober *fakeProber
}

func newServersEnv(t *testing.T, extraYAML string) *serversEnv {
	t.Helper()
	e := newSettingsEnv(t)
	src := serversYAML
	if extraYAML != "" {
		src = strings.Replace(src, "settings: { bmc_networks: [192.0.2.0/24] }", extraYAML, 1)
	}
	file, err := config.Parse([]byte(src))
	must(t, err)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cs, err := credstore.New(key)
	must(t, err)
	lg := audit.NewLogger(e.db.Audit(), nil, e.clock.Now, quiet())
	reg, err := registry.New(context.Background(), registry.Config{DB: e.db, Audit: lg, File: file, Creds: cs,
		Now: e.clock.Now, Logger: quiet()})
	must(t, err)
	prover, err := tofu.NewProver([]byte(strings.Repeat("t", 32)), e.clock.Now)
	must(t, err)
	p := &fakeProber{last: map[string]ServerTest{}}
	e.deps.Servers, e.deps.Prober, e.deps.Proofs = reg, p, prover
	app, err := New(e.deps)
	must(t, err)
	e.handler, err = web.NewHandler(app, web.Options{Logger: quiet()})
	must(t, err)
	return &serversEnv{settingsEnv: e, reg: reg, prober: p}
}

var hiddenInput = regexp.MustCompile(`name="(value|proof)" value="([^"]*)"`)

// fetchAndConfirm runs Add server: step 1 (fingerprint fetch), then the confirm form.
func (e *serversEnv) fetchAndConfirm(t *testing.T, c *client, id, address string) *httpResult {
	t.Helper()
	fields := url.Values{"id": {id}, "name": {"Edge " + id}, "tags": {"lab critical"}, "kind": {"idrac9"},
		"address": {address}, "port": {"443"}}
	page := result(c.submit("/settings/servers/new", "/settings/servers/fingerprint", fields)).status(t, http.StatusOK)
	body := page.rec.Body.String()
	got := map[string]string{}
	for _, m := range hiddenInput.FindAllStringSubmatch(body, -1) {
		got[m[1]] = m[2]
	}
	if got["value"] != spkiB || got["proof"] == "" {
		t.Fatalf("confirm page lacks the value or proof:\n%s", body)
	}
	for k, v := range got {
		fields[k] = []string{v}
	}
	fields[csrfField] = []string{csrfForAny(t, body, "/settings/servers")}
	return result(c.do(http.MethodPost, "/settings/servers", fields))
}

func TestServersListAndAccess(t *testing.T) {
	t.Parallel()
	e := newServersEnv(t, "")
	c := e.adminClient()
	result(c.get("/settings/servers")).status(t, http.StatusOK).contains(t, `aria-current="page">Servers`,
		"Storage node R730XD", "config.yaml", "Add server", "192.0.2.0/24", "Polling")
	viewer := e.signInViewer(t, "victor", "192.0.2.20")
	result(viewer.get("/settings/servers")).status(t, http.StatusForbidden)
	result(viewer.get("/settings/servers/r730xd")).status(t, http.StatusForbidden)
	if rec, ok := e.findAudit(string(authz.AdminServers), audit.ResultDenied); !ok || rec.Principal != "victor" {
		t.Fatalf("denial not audited: %+v", rec)
	}
}

func TestAddServerTOFUFlow(t *testing.T) {
	t.Parallel()
	e := newServersEnv(t, "")
	c := e.adminClient()
	confirm := result(c.submit("/settings/servers/new", "/settings/servers/fingerprint", url.Values{"id": {"edge1"},
		"name": {"Edge one"}, "kind": {"idrac9"}, "address": {"192.0.2.12"}, "port": {"443"}}))
	confirm.status(t, http.StatusOK).contains(t, "Confirm the HTTPS certificate", "fedc ba98 7654 3210",
		"CN=&lt;idrac&gt;&amp;co", "192.0.2.12:443")
	if confirm.rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("the confirm page is cacheable")
	}
	e.fetchAndConfirm(t, c, "edge2", "192.0.2.12").status(t, http.StatusSeeOther).
		location(t, "/settings/servers/edge2?done=server-created")
	x, ok := e.reg.Current().Entry("edge2")
	if !ok || x.Enabled || x.Server.TLSPinSHA256 != spkiB || strings.Join(x.Server.Tags, ",") != "lab,critical" {
		t.Fatalf("created = %+v", x)
	}
	if rec, ok := e.findAudit(registry.ActionCreate, audit.ResultOK); !ok || !strings.Contains(rec.ParamsJSON, `"pin_via":"tofu"`) {
		t.Fatalf("create audit = %+v", rec)
	}
	if rec, ok := e.findAudit(ActionServerFingerprint, audit.ResultOK); !ok || !strings.Contains(rec.ParamsJSON, `"address":"192.0.2.12"`) {
		t.Fatalf("fingerprint audit = %+v", rec)
	}
	result(c.get("/settings/servers/edge2?done=server-created")).status(t, http.StatusOK).contains(t,
		"Server added, disabled.", `aria-current="step"`, "Credentials", "Not set", "Enable server")
}

func TestAddServerRefusals(t *testing.T) {
	t.Parallel()
	e := newServersEnv(t, "")
	c := e.adminClient()
	post := func(addr, port, kind string) *httpResult {
		return result(c.submit("/settings/servers/new", "/settings/servers/fingerprint", url.Values{"id": {"x1"},
			"name": {"X"}, "kind": {kind}, "address": {addr}, "port": {port}}))
	}
	post("127.0.0.1", "443", "idrac9").status(t, http.StatusUnprocessableEntity).contains(t, "loopback", `aria-invalid="true"`)
	post("bmc.example.test", "443", "idrac9").status(t, http.StatusUnprocessableEntity).contains(t, "no host names")
	post("198.51.100.4", "443", "idrac9").status(t, http.StatusUnprocessableEntity).contains(t, "settings.bmc_networks")
	post("192.0.2.12", "80", "idrac9").status(t, http.StatusUnprocessableEntity).contains(t, "The port")
	post("192.0.2.12", "443", "ilo").status(t, http.StatusUnprocessableEntity)
	if n := e.prober.fetches(); n != 0 {
		t.Fatalf("a refused address was dialled (%d)", n)
	}
	// Tampered value: the proof does not match.
	fields := url.Values{"id": {"x2"}, "name": {"X"}, "kind": {"idrac9"}, "address": {"192.0.2.12"}, "port": {"443"},
		"value": {spkiA}, "proof": {"1.00"}, csrfField: {e.csrfToken(c)}}
	result(c.do(http.MethodPost, "/settings/servers", fields)).status(t, http.StatusUnprocessableEntity).
		contains(t, "could not be confirmed")
	// A config.yaml id cannot be added again.
	e.fetchAndConfirm(t, c, "r730xd", "192.0.2.13").status(t, http.StatusConflict).contains(t, "already exists")
	// Manual pin: created without a fetch, audited as manual.
	result(c.submit("/settings/servers/new", "/settings/servers/fingerprint", url.Values{"id": {"man1"}, "name": {"Manual"},
		"kind": {"idrac9"}, "address": {"192.0.2.14"}, "port": {"443"}, "pin": {strings.ToUpper(spkiA[:32]) + ":" + spkiA[32:]}})).
		status(t, http.StatusSeeOther)
	if x, _ := e.reg.Current().Entry("man1"); x.Server.TLSPinSHA256 != spkiA {
		t.Fatalf("manual pin = %q", x.Server.TLSPinSHA256)
	}
	if !e.auditContains(`"pin_via":"manual"`) {
		t.Fatal("manual pin not recorded")
	}
}

func TestServerCredentialsEnableAndTest(t *testing.T) {
	t.Parallel()
	e := newServersEnv(t, "")
	c := e.adminClient()
	e.fetchAndConfirm(t, c, "edge1", "192.0.2.12").status(t, http.StatusSeeOther)
	page := "/settings/servers/edge1"
	result(c.submit(page, page+"/enable", url.Values{"rev": {"1"}})).status(t, http.StatusUnprocessableEntity).
		contains(t, "credentials.readonly")
	result(c.submit(page, page+"/credentials/readonly", url.Values{"rev": {"1"}, "username": {"svc_ro"},
		"password": {roSecret}})).status(t, http.StatusSeeOther).location(t, page+"?done=server-credential#credentials")
	body := result(c.get(page)).status(t, http.StatusOK).contains(t, "Set · v1 · 2026-10-21 by morgan", "Replace").rec.Body.String()
	if strings.Contains(body, roSecret) || strings.Contains(body, "svc_ro") {
		t.Fatal("credential shown back")
	}
	result(c.submit(page, page+"/enable", url.Values{"rev": {"2"}})).status(t, http.StatusSeeOther)
	if x, _ := e.reg.Current().Entry("edge1"); !x.Active() {
		t.Fatalf("not active: %+v", x)
	}
	result(c.do(http.MethodPost, page+"/enable", url.Values{csrfField: {e.csrfToken(c)}, "rev": {"1"}})).status(t, http.StatusConflict)
	result(c.do(http.MethodPost, page+"/credentials/root", url.Values{csrfField: {e.csrfToken(c)}, "rev": {"3"},
		"password": {"x"}})).status(t, http.StatusNotFound)
	// Features, then Test connection.
	result(c.submit(page, page+"/features", url.Values{"rev": {"3"}, "fan_mode": {"none"}, "serial": {"none"},
		"graphical": {"link"}, "impact": {"Gateway: internet drops\n\n"}, "poll_interval_s": {"90"}})).status(t, http.StatusSeeOther)
	if x, _ := e.reg.Current().Entry("edge1"); x.Server.Console.Graphical != config.GraphicalLink || len(x.Server.Power.Impact) != 1 {
		t.Fatalf("features = %+v", x.Server.Console)
	}
	result(c.submit(page, page+"/features", url.Values{"rev": {"4"}, "fan_mode": {"none"}, "serial": {"bmcssh"},
		"graphical": {"none"}})).status(t, http.StatusUnprocessableEntity).contains(t, "credentials.operator")
	result(c.submit(page, page+"/test", nil)).status(t, http.StatusSeeOther).location(t, page+"?done=server-test#test")
	result(c.get(page)).contains(t, "Passed 2026-10-21", "Integrated Remote Access Controller.")
	if strings.Join(e.prober.tests, ",") != "edge1" {
		t.Fatalf("tests = %v", e.prober.tests)
	}
	if e.auditContains(roSecret) {
		t.Fatal("password in the audit log")
	}
	rows, _ := e.db.Credentials().All(context.Background())
	if len(rows) != 1 || strings.Contains(string(rows[0].SecretEnc), roSecret) {
		t.Fatal("credential stored in clear")
	}
}

func TestServerPinsAndMove(t *testing.T) {
	t.Parallel()
	e := newServersEnv(t, "")
	c := e.adminClient()
	e.fetchAndConfirm(t, c, "edge1", "192.0.2.12").status(t, http.StatusSeeOther)
	page := "/settings/servers/edge1"
	// Paste an SSH host key by hand.
	result(c.submit(page, page+"/pin", url.Values{"rev": {"1"}, "kind": {"ssh"}, "value": {hostKeyLine + " comment"}})).
		status(t, http.StatusSeeOther)
	if x, _ := e.reg.Current().Entry("edge1"); x.Server.SSHHostKey != hostKeyLine {
		t.Fatalf("host key = %q", x.Server.SSHHostKey)
	}
	result(c.submit(page, page+"/pin", url.Values{"rev": {"2"}, "kind": {"tls"}, "value": {"zz"}})).
		status(t, http.StatusUnprocessableEntity).contains(t, "64 hexadecimal")
	// Fetch-and-confirm the HTTPS pin again (a renewed certificate).
	conf := result(c.submit(page, page+"/pin/fetch", url.Values{"rev": {"2"}, "kind": {"tls"}})).status(t, http.StatusOK)
	if !strings.Contains(conf.rec.Body.String(), `action="/settings/servers/edge1/pin"`) {
		t.Fatal("pin confirm form missing")
	}
	// Move: credentials are cleared and the server is disabled.
	result(c.submit(page, page+"/credentials/readonly", url.Values{"rev": {"2"}, "username": {"u"}, "password": {roSecret}})).
		status(t, http.StatusSeeOther)
	result(c.submit(page, page+"/connection/fingerprint", url.Values{"rev": {"3"}, "kind": {"idrac9"},
		"address": {"192.0.2.99"}, "port": {"443"}, "pin": {spkiA}})).status(t, http.StatusSeeOther).
		location(t, page+"?done=server-moved#connection")
	x, _ := e.reg.Current().Entry("edge1")
	if x.Server.BMC.Address != "192.0.2.99" || len(x.Creds) != 0 || x.Server.SSHHostKey != "" || x.Server.TLSPinSHA256 != spkiA {
		t.Fatalf("after the move: %+v", x)
	}
}

func TestServerPageStates(t *testing.T) {
	t.Parallel()
	e := newServersEnv(t, "")
	e.fleet.servers[0].PinMismatch = true
	c := e.adminClient()
	result(c.get("/settings/servers/r730xd")).status(t, http.StatusOK).contains(t, "Managed by config.yaml",
		"Certificate changed", "From the age file (r-ro)").lacks(t, `action="/settings/servers/r730xd/identity"`,
		"Fetch the new fingerprint")
	result(c.do(http.MethodPost, "/settings/servers/r730xd/identity", url.Values{csrfField: {e.csrfToken(c)},
		"rev": {"0"}, "name": {"X"}})).status(t, http.StatusForbidden)
	result(c.get("/settings/servers/nope")).status(t, http.StatusNotFound)
	// Step-up: after the window a change is sent to the step-up page, its form kept (resume_test.go).
	e.clock.Advance(6 * time.Minute)
	resumeFrom(t, result(c.do(http.MethodPost, "/settings/servers/fingerprint", url.Values{csrfField: {e.csrfToken(c)}, "id": {"a"}})),
		"/settings/servers/new")
}

func TestRemoveServerTypedID(t *testing.T) {
	t.Parallel()
	e := newServersEnv(t, "")
	c := e.adminClient()
	e.fetchAndConfirm(t, c, "edge1", "192.0.2.12").status(t, http.StatusSeeOther)
	path := "/settings/servers/edge1/delete"
	result(c.get(path)).status(t, http.StatusOK).contains(t, "Remove Edge edge1?", "Cannot be undone")
	result(c.submit(path, path, url.Values{"confirm": {"yes"}, "typed": {"Edge edge1"}})).status(t, http.StatusUnprocessableEntity)
	result(c.submit(path, path, url.Values{"confirm": {"yes"}, "typed": {"edge1"}})).status(t, http.StatusSeeOther).
		location(t, "/settings/servers?done=server-deleted")
	if _, ok := e.reg.Current().Entry("edge1"); ok {
		t.Fatal("not removed")
	}
	if rec, ok := e.findAudit(registry.ActionDelete, audit.ResultOK); !ok || rec.ServerID != "edge1" {
		t.Fatalf("delete audit = %+v", rec)
	}
	result(c.get("/settings/servers/r730xd/delete")).status(t, http.StatusNotFound)
}

func TestDisableServerConfirm(t *testing.T) {
	t.Parallel()
	e := newServersEnv(t, "")
	c := e.adminClient()
	e.fetchAndConfirm(t, c, "edge1", "192.0.2.12").status(t, http.StatusSeeOther)
	page := "/settings/servers/edge1"
	result(c.submit(page, page+"/credentials/readonly", url.Values{"rev": {"1"}, "username": {"u"}, "password": {"p"}}))
	result(c.submit(page, page+"/enable", url.Values{"rev": {"2"}})).status(t, http.StatusSeeOther)
	path := page + "/disable"
	result(c.submit(path, path, url.Values{"confirm": {"yes"}, "typed": {"Edge edge1"}})).status(t, http.StatusSeeOther)
	if x, _ := e.reg.Current().Entry("edge1"); x.Enabled {
		t.Fatal("still enabled")
	}
}

func TestFingerprintRateLimitAndLock(t *testing.T) {
	t.Parallel()
	e := newServersEnv(t, "")
	c := e.adminClient()
	fields := url.Values{"id": {"x1"}, "name": {"X"}, "kind": {"idrac9"}, "address": {"192.0.2.12"}, "port": {"443"}}
	for range 6 {
		result(c.submit("/settings/servers/new", "/settings/servers/fingerprint", fields)).status(t, http.StatusOK)
	}
	result(c.submit("/settings/servers/new", "/settings/servers/fingerprint", fields)).status(t, http.StatusTooManyRequests)
	if n := e.prober.fetches(); n != 6 {
		t.Fatalf("fetches = %d", n)
	}
	lk := newServersEnv(t, "")
	lk.deps.Servers = nil
	app, err := New(lk.deps)
	must(t, err)
	lk.handler, err = web.NewHandler(app, web.Options{Logger: quiet()})
	must(t, err)
	result(lk.adminClient().get("/settings/servers")).status(t, http.StatusNotFound)
}

func TestFingerprintFetchError(t *testing.T) {
	t.Parallel()
	e := newServersEnv(t, "")
	e.prober.fail = &tofu.Error{Class: tofu.ClassNotTLS}
	c := e.adminClient()
	result(c.submit("/settings/servers/new", "/settings/servers/fingerprint", url.Values{"id": {"x1"}, "name": {"X"},
		"kind": {"idrac9"}, "address": {"192.0.2.12"}, "port": {"443"}})).status(t, http.StatusUnprocessableEntity).
		contains(t, "did not complete a TLS handshake")
	if rec, ok := e.findAudit(ActionServerFingerprint, audit.ResultError); !ok || rec.ErrorClass != "not_tls" {
		t.Fatalf("fetch error audit = %+v", rec)
	}
}

func TestServersLockedSection(t *testing.T) {
	t.Parallel()
	e := newServersEnv(t, "settings: { locked: [servers], bmc_networks: [192.0.2.0/24] }")
	c := e.adminClient()
	result(c.get("/settings/servers")).status(t, http.StatusOK).contains(t, "locked by <code>settings.locked</code>").
		lacks(t, `href="/settings/servers/new"`)
	result(c.get("/settings/servers/new")).status(t, http.StatusOK).lacks(t, "Fetch fingerprint")
	_, err := e.db.Servers().All(context.Background())
	must(t, err)
	_ = store.ErrNotFound
}

func TestServerAuditSentences(t *testing.T) {
	t.Parallel()
	e := newServersEnv(t, "")
	c := e.adminClient()
	e.fetchAndConfirm(t, c, "edge1", "192.0.2.12").status(t, http.StatusSeeOther)
	result(c.get("/settings/audit")).status(t, http.StatusOK).contains(t, "added server edge1", "fetched a BMC fingerprint")
}

func TestCertTextSanitised(t *testing.T) {
	t.Parallel()
	if got := certText("CN=a\u202egnp.exe\x00\n" + strings.Repeat("x", 300)); strings.ContainsAny(got, "\u202e\x00\n") ||
		len([]rune(got)) != maxCertText+1 || !strings.HasPrefix(got, "CN=agnp.exe") {
		t.Fatalf("certText = %q", got)
	}
	if certText("") != "(empty)" {
		t.Fatal("empty")
	}
}

// TestProofBoundToPurpose: a proof from Add server cannot confirm a pin of another
// server at the same address.
func TestProofBoundToPurpose(t *testing.T) {
	t.Parallel()
	e := newServersEnv(t, "")
	c := e.adminClient()
	e.fetchAndConfirm(t, c, "edge1", "192.0.2.12").status(t, http.StatusSeeOther)
	page := result(c.submit("/settings/servers/new", "/settings/servers/fingerprint", url.Values{"id": {"edge2"},
		"name": {"E2"}, "kind": {"idrac9"}, "address": {"192.0.2.12"}, "port": {"443"}})).status(t, http.StatusOK)
	got := map[string]string{}
	for _, m := range hiddenInput.FindAllStringSubmatch(page.rec.Body.String(), -1) {
		got[m[1]] = m[2]
	}
	result(c.do(http.MethodPost, "/settings/servers/edge1/pin", url.Values{csrfField: {e.csrfToken(c)}, "rev": {"1"},
		"kind": {"tls"}, "value": {got["value"]}, "proof": {got["proof"]}})).status(t, http.StatusUnprocessableEntity).
		contains(t, "could not be confirmed")
}

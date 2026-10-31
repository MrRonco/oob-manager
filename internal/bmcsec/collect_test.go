package bmcsec

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/bmcssh/sshtest"
	"oob-manager/internal/bmc/dellredfish"
	"oob-manager/internal/bmc/redfish"
	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/secprobe"
)

// lab is a mock BMC at a TEST-NET address: the dialer sends its ports to the fakes.
type lab struct {
	mock   *redfishmock.Server
	ssh    *sshtest.Server
	plain  *httptest.Server
	mu     sync.Mutex
	dialed []string
}

const labAddr = "192.0.2.10"

func newLab(t *testing.T, opts ...redfishmock.Option) *lab {
	t.Helper()
	l := &lab{mock: redfishmock.New(t, redfishmock.FixtureDir(t, "idrac9-r240"), append([]redfishmock.Option{redfishmock.WithWSMan()}, opts...)...),
		ssh: sshtest.New(t, sshtest.Options{})}
	l.plain = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+labAddr+"/", http.StatusMovedPermanently)
	}))
	t.Cleanup(l.plain.Close)
	return l
}

func (l *lab) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	l.mu.Lock()
	l.dialed = append(l.dialed, addr)
	l.mu.Unlock()
	targets := map[string]string{
		labAddr + ":443": strings.TrimPrefix(l.mock.URL(), "https://"),
		labAddr + ":22":  l.ssh.Addr(),
		labAddr + ":80":  strings.TrimPrefix(l.plain.URL, "http://"),
	}
	to, ok := targets[addr]
	if !ok {
		return nil, errors.New("lab: nothing at " + addr)
	}
	return (&net.Dialer{}).DialContext(ctx, network, to)
}

func (l *lab) dials(port string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, a := range l.dialed {
		if strings.HasSuffix(a, ":"+port) {
			n++
		}
	}
	return n
}

func (l *lab) driver(t *testing.T) *dellredfish.Driver {
	t.Helper()
	d, err := dellredfish.New(redfish.Config{Endpoint: l.mock.URL(), Username: redfishmock.User, Password: redfishmock.Password,
		PinSHA256: l.mock.PinSHA256(), Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (l *lab) target(t *testing.T) Target {
	t.Helper()
	pin, err := hex.DecodeString(l.mock.PinSHA256())
	if err != nil {
		t.Fatal(err)
	}
	return Target{Addr: netip.MustParseAddr(labAddr), HTTPSPort: 443, Pin: pin}
}

func (l *lab) collector() Collector {
	return Collector{Probe: secprobe.Options{Dial: l.dial, HandshakeTimeout: 2 * time.Second, ProbeGap: time.Millisecond}}
}

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestCollectReadsRedfishAndProbesOnlyReading(t *testing.T) {
	l := newLab(t, redfishmock.WithTokenOnly())
	p, err := l.collector().Collect(ctxT(t), l.driver(t), l.target(t))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Redfish.Protocols.Read.OK() || !p.Redfish.Attributes.OK() || !p.Web.Usable() || !p.SSH.Read.OK() ||
		!p.HTTP.ToHTTPS || p.WSMan.Status != 401 || p.WSMan.ControlStatus != 404 || p.Started.IsZero() || p.Duration <= 0 {
		t.Fatalf("posture %+v", p)
	}
	if p.VNC.Read.State != bmc.ReadNotTried {
		t.Fatalf("VNC is not configured: %+v", p.VNC.Read)
	}
	// The whole run: GET and HEAD only (plus the one session login), no SSH login.
	for _, r := range l.mock.Requests() {
		login := r.Method == http.MethodPost && r.Path == l.mock.SessionsURI()
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !login {
			t.Fatalf("the checks sent %s %s", r.Method, r.Path)
		}
	}
	if l.mock.OtherWrites() != 0 || l.mock.SessionStats().Created != 1 || l.mock.Heads() != 2 {
		t.Fatalf("writes %d sessions %+v heads %d", l.mock.OtherWrites(), l.mock.SessionStats(), l.mock.Heads())
	}
	if l.ssh.AuthAttempts() != 0 || l.ssh.Sessions() != 0 {
		t.Fatal("the SSH probe must not log in")
	}
	r := Evaluate("r240", p, Inputs{Kind: "idrac9"}, time.Now())
	if f, _ := r.Finding("svc.http"); f.Result != Pass {
		t.Fatalf("a redirect to HTTPS passes: %+v", f)
	}
}

// vncOn makes the lab's BMC report its VNC server on (the iDRAC9 fixture reports it off): the
// DMTF document says so and the Dell attribute documents, which would override it, are absent.
func vncOn() []redfishmock.Option {
	return []redfishmock.Option{
		redfishmock.WithOverlay("/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol", `{"RFB":{"ProtocolEnabled":true,"Port":5901},"SSH":{"ProtocolEnabled":true,"Port":22},"HTTP":{"ProtocolEnabled":true,"Port":80}}`),
		redfishmock.WithMissing("/redfish/v1/Managers/iDRAC.Embedded.1/Attributes"),
		redfishmock.WithMissing("/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1"),
	}
}

func TestCollectSkipsVNCWhileAConsoleIsOpen(t *testing.T) {
	l := newLab(t, vncOn()...)
	tg := l.target(t)
	tg.VNC = &VNCTarget{Port: 5901, Pin: tg.Pin}
	tg.ConsoleActive = func() bool { return true }
	p, err := l.collector().Collect(ctxT(t), l.driver(t), tg)
	if err != nil {
		t.Fatal(err)
	}
	if p.VNC.Read.State != bmc.ReadSkipped || l.dials("5901") != 0 {
		t.Fatalf("VNC probed during a console session: %+v dials %d", p.VNC.Read, l.dials("5901"))
	}
	tg.ConsoleActive = func() bool { return false }
	p, _ = l.collector().Collect(ctxT(t), l.driver(t), tg)
	if p.VNC.Read.State != bmc.ReadFailed || l.dials("5901") != 1 {
		t.Fatalf("VNC probed when idle (nothing listens in the lab): %+v", p.VNC.Read)
	}
}

func TestCollectSkipsServicesTheBMCReportsOff(t *testing.T) {
	np := `{"SSH":{"ProtocolEnabled":false,"Port":22},"HTTP":{"ProtocolEnabled":false,"Port":80},"IPMI":{"ProtocolEnabled":false}}`
	l := newLab(t, redfishmock.WithOverlay("/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol", np),
		redfishmock.WithMissing("/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1"))
	p, err := l.collector().Collect(ctxT(t), l.driver(t), l.target(t))
	if err != nil {
		t.Fatal(err)
	}
	if p.SSH.Read.State != bmc.ReadSkipped || p.HTTP.Read.State != bmc.ReadSkipped || l.dials("22") != 0 || l.dials("80") != 0 {
		t.Fatalf("services that are off are not probed: %+v %+v", p.SSH.Read, p.HTTP.Read)
	}
}

func TestCollectUsesConfiguredAndReportedPorts(t *testing.T) {
	tg := Target{SSHPort: 2222}
	if port, ok := sshPort(tg, bmc.ProtocolFacts{SSHPort: bmc.FactOf(22, "np")}); !ok || port != 2222 {
		t.Fatalf("configured serial SSH port wins: %d", port)
	}
	if port, ok := sshPort(Target{}, bmc.ProtocolFacts{SSHPort: bmc.FactOf(2200, "np")}); !ok || port != 2200 {
		t.Fatalf("BMC-reported port: %d", port)
	}
	if port, ok := httpPort(bmc.ProtocolFacts{}); !ok || port != 80 {
		t.Fatalf("default HTTP port: %d", port)
	}
	if port, ok := httpPort(bmc.ProtocolFacts{HTTPPort: bmc.FactOf(8080, "np")}); !ok || port != 8080 {
		t.Fatalf("reported HTTP port: %d", port)
	}
}

func TestCollectWSManNeedsThePinnedCertificate(t *testing.T) {
	l := newLab(t)
	tg := l.target(t)
	tg.Pin = make([]byte, 32)
	p, err := l.collector().Collect(ctxT(t), l.driver(t), tg)
	if err != nil {
		t.Fatal(err)
	}
	if p.Web.PinMatch || p.WSMan.Read.State != bmc.ReadSkipped || l.mock.Heads() != 0 {
		t.Fatalf("an unpinned host gets no HEAD: %+v heads %d", p.WSMan.Read, l.mock.Heads())
	}
}

type plainDriver struct{ bmc.Driver }

func TestCollectErrors(t *testing.T) {
	l := newLab(t)
	if _, err := l.collector().Collect(ctxT(t), plainDriver{}, l.target(t)); !errors.Is(err, bmc.ErrUnsupported) {
		t.Fatalf("a driver without posture: %v", err)
	}
	l.mock.SetDown(true)
	if _, err := l.collector().Collect(ctxT(t), l.driver(t), l.target(t)); err == nil {
		t.Fatal("nothing read: the run fails")
	}
}

// TestVNCProbeTargetReadsTheCertificateOnlyAndStopsForTheConsole: the VNC port gets one
// handshake (the certificate; the version and suite checks apply to the web port), with
// the identity suites the port needs, and the probe is told to stop when a graphical
// console session opens meanwhile.
func TestVNCProbeTargetReadsTheCertificateOnlyAndStopsForTheConsole(t *testing.T) {
	open := false
	tg := Target{Addr: netip.MustParseAddr(labAddr), VNC: &VNCTarget{Port: 5901, Pin: make([]byte, 32), RSAKeyExchange: true},
		ConsoleActive: func() bool { return open }}
	pt := vncProbeTarget(tg)
	if !pt.IdentityOnly || !pt.RSAKeyExchange || pt.Addr.Port() != 5901 || pt.Addr.Addr().String() != labAddr || len(pt.Pin) != 32 {
		t.Fatalf("target %+v", pt)
	}
	if pt.Abort == nil || pt.Abort() != "" {
		t.Fatal("an idle console must not stop the probe")
	}
	open = true
	if pt.Abort() != consoleOpened {
		t.Fatalf("abort %q", pt.Abort())
	}
	if pt := vncProbeTarget(Target{VNC: &VNCTarget{Port: 5901}}); pt.Abort == nil || pt.Abort() != "" {
		t.Fatal("without a console state the probe is never stopped")
	}
}

// TestCollectFailsWhenTheRunIsCutShort: a run whose context expires while a probe hangs
// is a failed run (the fleet keeps the previous posture and retries soon), not a posture
// with holes in it.
func TestCollectFailsWhenTheRunIsCutShort(t *testing.T) {
	l := newLab(t)
	hang := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasSuffix(addr, ":22") {
			<-ctx.Done() // the SSH port never answers
			return nil, ctx.Err()
		}
		return l.dial(ctx, network, addr)
	}
	col := Collector{Probe: secprobe.Options{Dial: hang, HandshakeTimeout: 2 * time.Second, ProbeGap: time.Millisecond}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := col.Collect(ctx, l.driver(t), l.target(t)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a run cut short by its deadline must fail: %v", err)
	}
}

// TestPostureTransportFailure: the class of a probe section that failed to reach the
// BMC (timeout, unreachable), which the fleet treats as a failed run; a refused plain-HTTP
// port is a result, not a failure.
func TestPostureTransportFailure(t *testing.T) {
	p := good()
	if c := p.TransportFailure(); c != bmc.ClassNone {
		t.Fatalf("a good posture: %q", c)
	}
	p.SSH.Read = bmc.Section{State: bmc.ReadFailed, Class: bmc.ClassTimeout}
	if c := p.TransportFailure(); c != bmc.ClassTimeout {
		t.Fatalf("SSH timeout: %q", c)
	}
	p = good()
	p.HTTP = bmc.HTTPProbe{Read: bmc.Section{State: bmc.ReadFailed, Class: bmc.ClassUnreachable}, Refused: true, Port: 80}
	if c := p.TransportFailure(); c != bmc.ClassNone {
		t.Fatalf("a closed HTTP port is a result: %q", c)
	}
	p.HTTP.Refused = false
	if c := p.TransportFailure(); c != bmc.ClassUnreachable {
		t.Fatalf("an unreachable HTTP port: %q", c)
	}
	p = good()
	p.WSMan.Read = bmc.Section{State: bmc.ReadFailed, Class: bmc.ClassProtocol}
	if c := p.TransportFailure(); c != bmc.ClassNone {
		t.Fatalf("a protocol error is an answer, not a transport failure: %q", c)
	}
	// A VNC or SSH port that refused the connection is a closed port: a result, not a failure.
	p = good()
	p.VNC = bmc.TLSProbe{Read: bmc.Section{State: bmc.ReadFailed, Class: bmc.ClassUnreachable}, Refused: true, Port: 5901}
	p.SSH = bmc.SSHProbe{Read: bmc.Section{State: bmc.ReadFailed, Class: bmc.ClassUnreachable}, Refused: true, Port: 22}
	if c := p.TransportFailure(); c != bmc.ClassNone {
		t.Fatalf("refused VNC and SSH ports are results: %q", c)
	}
	p.SSH.Refused = false
	if c := p.TransportFailure(); c != bmc.ClassUnreachable {
		t.Fatalf("an unreachable SSH port: %q", c)
	}
	// The VNC port never fails a run: it serves one client at a time, so a timeout or an
	// unanswered connection there is expected while another session holds it.
	for _, class := range []bmc.ErrorClass{bmc.ClassTimeout, bmc.ClassUnreachable} {
		p = good()
		p.VNC = bmc.TLSProbe{Read: bmc.Section{State: bmc.ReadFailed, Class: class}, Port: 5901}
		if c := p.TransportFailure(); c != bmc.ClassNone {
			t.Fatalf("a VNC port that failed with %q failed the run: %q", class, c)
		}
	}
}

// TestCollectLeavesAnIDRAC8VNCPortAlone: the VNC port of an iDRAC8 is never dialled (its
// single-client server stays busy for minutes after each connection), the run is kept,
// and the certificate check says why it did not run.
func TestCollectLeavesAnIDRAC8VNCPortAlone(t *testing.T) {
	l := newLab(t, vncOn()...)
	tg := l.target(t)
	tg.VNC = &VNCTarget{Port: 5901, Pin: tg.Pin, RSAKeyExchange: true, NotProbed: NotProbedIDRAC8}
	p, err := l.collector().Collect(ctxT(t), l.driver(t), tg)
	if err != nil {
		t.Fatal(err)
	}
	if p.VNC.Read.State != bmc.ReadSkipped || p.VNC.Read.Why != NotProbedIDRAC8 || p.VNC.Port != 5901 || l.dials("5901") != 0 {
		t.Fatalf("the iDRAC8 VNC port was probed: %+v dials %d", p.VNC.Read, l.dials("5901"))
	}
	if c := p.TransportFailure(); c != bmc.ClassNone {
		t.Fatalf("a port left alone is not a failed run: %q", c)
	}
	r := Evaluate("r730xd", p, Inputs{Kind: "idrac8", VNC: true, VNCTLS: true}, time.Now())
	f, ok := r.Finding("tls.vnc_cert")
	// A by-design skip is a note (info), not an unknown that never resolves.
	if !ok || f.Result != Info || len(f.Evidence) != 1 || !strings.HasPrefix(f.Evidence[0], "Not checked: an iDRAC8 takes one VNC client") ||
		!strings.HasSuffix(f.Evidence[0], "which the web checks cover.") {
		t.Fatalf("VNC certificate finding: %+v", f)
	}
}

// TestCollectIDRAC8VNCOffSaysOff: with the VNC server reported off, the more precise
// reason wins over the iDRAC8 rule (the case order in Collector.vnc).
func TestCollectIDRAC8VNCOffSaysOff(t *testing.T) {
	l := newLab(t) // the iDRAC9 fixture reports the VNC server off
	tg := l.target(t)
	tg.VNC = &VNCTarget{Port: 5901, Pin: tg.Pin, NotProbed: NotProbedIDRAC8}
	p, err := l.collector().Collect(ctxT(t), l.driver(t), tg)
	if err != nil {
		t.Fatal(err)
	}
	if p.VNC.Read.State != bmc.ReadSkipped || p.VNC.Read.Why != "the BMC reports its VNC server off" || l.dials("5901") != 0 {
		t.Fatalf("VNC section %+v dials %d", p.VNC.Read, l.dials("5901"))
	}
}

// TestCollectNeverReachesALeftAloneVNCPortThroughAReportedPort: a BMC reporting SSH or
// plain HTTP on the VNC port the checks leave alone does not get them to open it.
func TestCollectNeverReachesALeftAloneVNCPortThroughAReportedPort(t *testing.T) {
	l := newLab(t, redfishmock.WithOverlay("/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol",
		`{"RFB":{"ProtocolEnabled":true,"Port":5901},"SSH":{"ProtocolEnabled":true,"Port":5901},"HTTP":{"ProtocolEnabled":true,"Port":5901}}`),
		redfishmock.WithMissing("/redfish/v1/Managers/iDRAC.Embedded.1/Attributes"),
		redfishmock.WithMissing("/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1"))
	tg := l.target(t)
	tg.SSHPort = 0
	tg.VNC = &VNCTarget{Port: 5901, Pin: tg.Pin, NotProbed: NotProbedIDRAC8}
	p, err := l.collector().Collect(ctxT(t), l.driver(t), tg)
	if err != nil {
		t.Fatal(err)
	}
	if l.dials("5901") != 0 || p.SSH.Read.Why != onVNCPort || p.HTTP.Read.Why != onVNCPort {
		t.Fatalf("dials %d, SSH %+v, HTTP %+v", l.dials("5901"), p.SSH.Read, p.HTTP.Read)
	}
	if c := p.TransportFailure(); c != bmc.ClassNone {
		t.Fatalf("skipped probes are not a failed run: %q", c)
	}
}

// TestCollectSkipsVNCTheBMCReportsOff: a VNC server the BMC reports off is not probed,
// whatever the console configuration says (nothing listens; a refusal there is not a
// failed run).
func TestCollectSkipsVNCTheBMCReportsOff(t *testing.T) {
	l := newLab(t) // the iDRAC9 fixture reports the VNC server off
	tg := l.target(t)
	tg.VNC = &VNCTarget{Port: 5901, Pin: tg.Pin}
	p, err := l.collector().Collect(ctxT(t), l.driver(t), tg)
	if err != nil {
		t.Fatal(err)
	}
	if p.VNC.Read.State != bmc.ReadSkipped || !strings.Contains(p.VNC.Read.Why, "off") || l.dials("5901") != 0 {
		t.Fatalf("VNC probed although the BMC reports it off: %+v dials %d", p.VNC.Read, l.dials("5901"))
	}
	if c := p.TransportFailure(); c != bmc.ClassNone {
		t.Fatalf("a skipped port is not a failure: %q", c)
	}
}

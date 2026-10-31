package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/dellredfish"
	"oob-manager/internal/bmc/redfish"
	"oob-manager/internal/config"
	"oob-manager/internal/console"
	"oob-manager/internal/notify"
	"oob-manager/internal/registry"
	"oob-manager/internal/secrets"
	"oob-manager/internal/secrets/credstore"
	"oob-manager/internal/tofu"
	"oob-manager/internal/web/ui"
)

// testSlack is added to a server's cycle timeout to bound a whole Test connection.
const testSlack = 30 * time.Second

// ActionServerTest is the audit action of a finished Test connection.
const ActionServerTest = "admin.server.test"

// prober implements ui.ServerProber: handshake-only fingerprint fetches and the
// read-only Test connection (Redfish service root, system and manager, licence, reset
// actions, fan limits, VNC banner, SSH host key). Nothing is written to a BMC: the only
// non-GET is the Redfish session login and logout that every poll also does.
type prober struct {
	reg   *registry.Service
	file  secrets.Credentials
	e     env
	audit *audit.Logger
	log   *slog.Logger
	now   func() time.Time
	// trust reports pinned-key checks to the notifications (notify.Tap.Trust).
	trust func(serverID, what string, ok bool)

	mu   sync.Mutex
	last map[string]ui.ServerTest
}

func newProber(reg *registry.Service, file secrets.Credentials, e env, aud *audit.Logger, log *slog.Logger) *prober {
	return &prober{reg: reg, file: file, e: e, audit: aud, log: log, now: time.Now, last: map[string]ui.ServerTest{},
		trust: func(string, string, bool) {}}
}

func (p *prober) opts() tofu.Options { return tofu.Options{Dial: p.e.bmcDial} }

// FetchTLS implements ui.ServerProber.
func (p *prober) FetchTLS(ctx context.Context, addr netip.AddrPort, rsaKex bool) (tofu.CertInfo, error) {
	o := p.opts()
	o.RSAKeyExchange = rsaKex
	return tofu.FetchTLS(ctx, addr, o)
}

// FetchSSH implements ui.ServerProber.
func (p *prober) FetchSSH(ctx context.Context, addr netip.AddrPort, legacy bool) (tofu.HostKey, error) {
	return tofu.FetchSSHHostKey(ctx, addr, tofu.SSHOptions{Options: p.opts(), Legacy: legacy})
}

// LastTest implements ui.ServerProber.
func (p *prober) LastTest(id string) (ui.ServerTest, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, ok := p.last[id]
	return t, ok
}

// StartTest implements ui.ServerProber.
func (p *prober) StartTest(id, by string) error {
	x, ok := p.reg.Current().Entry(id)
	if !ok {
		return registry.ErrNotFound
	}
	p.mu.Lock()
	if cur, running := p.last[id]; running && cur.Running {
		p.mu.Unlock()
		return ui.ErrTestRunning
	}
	p.last[id] = ui.ServerTest{Running: true, By: by, StartedAt: p.now()}
	p.mu.Unlock()
	go p.runTest(x, by)
	return nil
}

func (p *prober) runTest(x registry.Entry, by string) {
	s := x.Server
	ctx, cancel := context.WithTimeout(context.Background(), s.BMC.Timeouts.Cycle+testSlack)
	defer cancel()
	res := ui.ServerTest{By: by}
	p.mu.Lock()
	res.StartedAt = p.last[s.ID].StartedAt
	p.mu.Unlock()
	res.Kind, res.Steps = p.redfishSteps(ctx, x)
	if s.Console.Graphical == config.GraphicalVNC {
		res.Steps = append(res.Steps, p.vncStep(ctx, s))
	}
	if s.Console.Serial == config.SerialBMCSSH {
		res.Steps = append(res.Steps, p.sshStep(ctx, s))
	}
	res.OK = true
	for _, st := range res.Steps {
		res.OK = res.OK && st.OK
	}
	res.FinishedAt = p.now()
	// Audit first: once the result is visible as finished, its audit row already exists.
	p.record(s.ID, by, res)
	p.mu.Lock()
	p.last[s.ID] = res
	p.mu.Unlock()
}

func (p *prober) record(id, by string, res ui.ServerTest) {
	e := audit.Entry{Principal: by, AuthMethod: "local", ServerID: id, Action: ActionServerTest, Result: audit.ResultOK,
		Params: map[string]any{"target": "server:" + id, "kind_detected": string(res.Kind)}}
	if !res.OK {
		e.Result = audit.ResultError
		for _, st := range res.Steps {
			if !st.OK {
				e.ErrorClass = strings.ToLower(strings.ReplaceAll(st.Name, " ", "_"))
				break
			}
		}
	}
	if _, err := p.audit.Record(context.Background(), e); err != nil {
		p.log.Error("servers: test audit failed", "server", id, "err", err)
	}
}

// login is the server's read-only credential, from the age file or the database.
func (p *prober) login(ctx context.Context, x registry.Entry) (secrets.Credential, error) {
	if x.Source == registry.SourceDB {
		return p.reg.Credential(ctx, x.Server.ID, credstore.SlotReadOnly)
	}
	return p.file.Lookup(x.Server.Credentials.ReadOnly)
}

func (p *prober) endpoint(s config.Server) string {
	if p.e.kvmEndpoint != nil {
		return p.e.kvmEndpoint(s)
	}
	return s.BMC.Endpoint()
}

// redfishSteps reads the service root, system and manager (Probe), the licence and,
// on an iDRAC9, the fan floor limits; it reports the kind the answers suggest.
func (p *prober) redfishSteps(ctx context.Context, x registry.Entry) (config.BMCKind, []ui.TestStep) {
	s := x.Server
	ro, err := p.login(ctx, x)
	if err != nil {
		return "", []ui.TestStep{{Name: "Read-only login", Detail: "Not stored or cannot be opened. Enter it again."}}
	}
	d, err := p.e.newDriver(s, ro)
	if err != nil {
		return "", []ui.TestStep{{Name: "Redfish", Detail: "No driver for this kind of BMC."}}
	}
	if c, ok := d.(interface{ Close(context.Context) error }); ok {
		defer func() { _ = c.Close(context.WithoutCancel(ctx)) }()
	}
	caps, err := d.Probe(ctx)
	if err != nil {
		return "", []ui.TestStep{{Name: "Redfish", Detail: "Failed: " + string(bmc.Classify(err)) + "."}}
	}
	f := caps.Flags()
	kind := detectKind(f)
	steps := []ui.TestStep{
		{Name: "Redfish", OK: true, Detail: fmt.Sprintf("%s, Redfish %s.", nonEmpty(f.Product), nonEmpty(f.RedfishVersion))},
		kindStep(s.BMC.Kind, kind),
		{Name: "Firmware", OK: true, Detail: fmt.Sprintf("%s, firmware %s.", nonEmpty(f.BMCModel), nonEmpty(f.BMCFirmware))},
		{Name: "Reset actions", OK: true, Detail: resetDetail(caps.ResetTypes())},
	}
	if lic, ok := d.(interface {
		License(context.Context) (bmc.License, error)
	}); ok {
		steps = append(steps, licenseStep(ctx, lic))
	}
	if kind == config.KindIDRAC9 {
		steps = append(steps, p.fanStep(ctx, s, ro))
	}
	return kind, steps
}

func (p *prober) fanStep(ctx context.Context, s config.Server, ro secrets.Credential) ui.TestStep {
	c := dellredfish.NewFanFloorClient(redfish.Config{Endpoint: p.endpoint(s), Username: ro.Username,
		Password: ro.Password.Reveal(), PinSHA256: s.TLSPinSHA256, Timeout: s.BMC.Timeouts.Request,
		Auth: redfish.AuthMode(s.BMC.Auth)})
	ff, err := c.Read(ctx)
	if err != nil {
		return ui.TestStep{Name: "Fan limits", OK: true, Detail: "Not readable with the read-only login (" + string(bmc.Classify(err)) + ")."}
	}
	cur := "automatic"
	if !ff.Automatic() {
		cur = fmt.Sprintf("%d %%", ff.Current)
	}
	return ui.TestStep{Name: "Fan limits", OK: true, Detail: fmt.Sprintf("Minimum fan speed %s; the BMC accepts %d–%d %%.", cur, ff.Low, ff.High)}
}

func (p *prober) vncStep(ctx context.Context, s config.Server) ui.TestStep {
	t, err := console.TargetFor(s, secrets.Secret{})
	if err != nil {
		return ui.TestStep{Name: "VNC banner", Detail: "The VNC settings are incomplete."}
	}
	dial := console.DialFunc(p.e.vncDial)
	if dial == nil && p.e.bmcDial != nil {
		dial = console.DialFunc(p.e.bmcDial)
	}
	pr := console.ProbeBanner(ctx, dial, t, p.now())
	switch pr.State {
	case console.ProbePin:
		p.trust(s.ID, notify.TrustVNC, false)
	case console.ProbeOK:
		p.trust(s.ID, notify.TrustVNC, true)
	}
	if pr.State != console.ProbeOK {
		return ui.TestStep{Name: "VNC banner", Detail: "No RFB banner: " + string(pr.State) + "."}
	}
	return ui.TestStep{Name: "VNC banner", OK: true, Detail: fmt.Sprintf("RFB 3.%d answered over the pinned connection.", pr.Version)}
}

func (p *prober) sshStep(ctx context.Context, s config.Server) ui.TestStep {
	addr, err := netip.ParseAddrPort(net.JoinHostPort(s.BMC.Address, fmt.Sprint(s.Console.SSH.Port)))
	if err != nil {
		return ui.TestStep{Name: "SSH host key", Detail: "The SSH address is not valid."}
	}
	o := p.opts()
	if p.e.sshDial != nil {
		o.Dial = tofu.Dialer(p.e.sshDial)
	}
	key, err := tofu.FetchSSHHostKey(ctx, addr, tofu.SSHOptions{Options: o, Legacy: s.Console.SSH.Has(config.QuirkIDRAC8LegacySSH)})
	switch {
	case err != nil:
		return ui.TestStep{Name: "SSH host key", Detail: "Not read: " + classOf(err) + "."}
	case s.SSHHostKey == "":
		return ui.TestStep{Name: "SSH host key", Detail: key.Fingerprint + " (" + key.Type + "); not confirmed yet."}
	case key.Line != strings.Join(strings.Fields(s.SSHHostKey)[:2], " "):
		p.trust(s.ID, notify.TrustSSHKey, false)
		return ui.TestStep{Name: "SSH host key", Detail: key.Fingerprint + " does NOT match the confirmed key. The serial console refuses it."}
	default:
		p.trust(s.ID, notify.TrustSSHKey, true)
		return ui.TestStep{Name: "SSH host key", OK: true, Detail: key.Fingerprint + " matches the confirmed key."}
	}
}

func classOf(err error) string {
	if te, ok := err.(*tofu.Error); ok { //nolint:errorlint // tofu returns *Error unwrapped
		return string(te.Class)
	}
	return "error"
}

// detectKind reads a Dell iDRAC generation from the manager model ("13G …" is iDRAC8,
// 14G and later iDRAC9); anything else is a generic Redfish BMC.
func detectKind(f bmc.CapabilityFlags) config.BMCKind {
	if !strings.Contains(f.Product, "Remote Access Controller") && !strings.Contains(f.BMCModel, "iDRAC") {
		return config.KindRedfish
	}
	switch {
	case strings.HasPrefix(f.BMCModel, "12G"), strings.HasPrefix(f.BMCModel, "13G"):
		return config.KindIDRAC8
	case strings.HasPrefix(f.BMCFirmware, "2."):
		return config.KindIDRAC8
	default:
		return config.KindIDRAC9
	}
}

func kindStep(configured, detected config.BMCKind) ui.TestStep {
	if configured == detected {
		return ui.TestStep{Name: "Kind", OK: true, Detail: "Looks like " + string(detected) + ", as configured."}
	}
	return ui.TestStep{Name: "Kind", Detail: "Looks like " + string(detected) + ", but the server is set to " + string(configured) + "."}
}

func licenseStep(ctx context.Context, d interface {
	License(context.Context) (bmc.License, error)
}) ui.TestStep {
	l, err := d.License(ctx)
	if err != nil {
		return ui.TestStep{Name: "License", OK: true, Detail: "Not readable (" + string(bmc.Classify(err)) + ")."}
	}
	return ui.TestStep{Name: "License", OK: true, Detail: string(l.Tier) + " (" + nonEmpty(l.Description) + ")."}
}

func resetDetail(types []string) string {
	if len(types) == 0 {
		return "The BMC offers no reset actions."
	}
	return "Offered: " + strings.Join(types, ", ") + "."
}

func nonEmpty(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

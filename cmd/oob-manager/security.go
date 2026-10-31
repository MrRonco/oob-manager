package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"strconv"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmcsec"
	"oob-manager/internal/config"
	"oob-manager/internal/fleet"
	"oob-manager/internal/metrics"
	"oob-manager/internal/notify"
	"oob-manager/internal/secprobe"
	"oob-manager/internal/web/ui"
)

// The security check service is the UI's Security tab (tech_doc §31).
var _ ui.Security = (*bmcsec.Service)(nil)

// errProbeDialOff refuses a security probe when env.probeDial is not set.
var errProbeDialOff = errors.New("security checks: no probe dialer is configured")

// probeDialer is env.probeDial, or a dialer that refuses every address: an env built
// without one (any test) never reaches the network from a security probe.
func probeDialer(e env) secprobe.Dialer {
	if e.probeDial != nil {
		return e.probeDial
	}
	return func(context.Context, string, string) (net.Conn, error) { return nil, errProbeDialOff }
}

// securityKind reports a BMC kind with a posture reader (the Redfish drivers).
func securityKind(k config.BMCKind) bool {
	return k == config.KindIDRAC8 || k == config.KindIDRAC9 || k == config.KindRedfish
}

// postureFor is server s's security check reader, bound to its settings, or nil when the
// checks are off or the kind has none. It runs on the poller's own driver (fleet.Target).
func (rt *serverRuntime) postureFor(s config.Server) fleet.PostureFunc {
	if !rt.base.Security.On() || !securityKind(s.BMC.Kind) {
		return nil
	}
	t, err := securityTarget(s, rt.vncInUse)
	if err != nil {
		rt.log.Warn("security checks skipped: the BMC address or a pin cannot be read", "server", s.ID, "err", err)
		return nil
	}
	col := bmcsec.Collector{Probe: secprobe.Options{Dial: probeDialer(rt.e)}}
	return func(ctx context.Context, d bmc.Driver) (bmc.Posture, error) { return col.Collect(ctx, d, t) }
}

// vncInUse reports an open graphical console on server id (its VNC port is then left
// alone until the next run).
func (rt *serverRuntime) vncInUse(id string) bool {
	return rt.cd.svc != nil && rt.cd.svc.Status(id).InUse
}

// vncNotProbed is why the checks leave a kind's VNC port alone ("" to probe it): an
// iDRAC8's single-client VNC server stays busy for minutes after each connection.
func vncNotProbed(k config.BMCKind) string {
	if k == config.KindIDRAC8 {
		return bmcsec.NotProbedIDRAC8
	}
	return ""
}

// securityTarget is what the checks probe on s, all from the validated config: the BMC
// address and Redfish port with the pinned key, the VNC port when the graphical console
// is VNC over TLS, and the serial console's SSH port. inUse (nil: never) is read live.
func securityTarget(s config.Server, inUse func(id string) bool) (bmcsec.Target, error) {
	addr, err := netip.ParseAddr(s.BMC.Address)
	if err != nil {
		return bmcsec.Target{}, fmt.Errorf("bmc.address: %w", err)
	}
	pin, err := hex.DecodeString(s.TLSPinSHA256)
	if err != nil {
		return bmcsec.Target{}, fmt.Errorf("tls_pin_sha256: %w", err)
	}
	t := bmcsec.Target{Addr: addr.Unmap(), HTTPSPort: port16(s.BMC.Port), Pin: pin}
	if s.Console.Graphical == config.GraphicalVNC && s.Console.VNC.TLSEnabled() {
		vpin, err := hex.DecodeString(s.VNCPin())
		if err != nil {
			return bmcsec.Target{}, fmt.Errorf("console.vnc.tls_pin_sha256: %w", err)
		}
		t.VNC = &bmcsec.VNCTarget{Port: port16(s.Console.VNC.Port), Pin: vpin,
			RSAKeyExchange: s.Console.VNC.Has(config.QuirkIDRAC8RSAKexTLS), NotProbed: vncNotProbed(s.BMC.Kind)}
	}
	if s.Console.Serial == config.SerialBMCSSH {
		t.SSHPort = port16(s.Console.SSH.Port)
	}
	if inUse != nil {
		id := s.ID
		t.ConsoleActive = func() bool { return inUse(id) }
	}
	return t, nil
}

// port16 is a validated config port; anything outside 1–65535 is 0.
func port16(n int) uint16 {
	if n < 1 || n > math.MaxUint16 {
		return 0
	}
	return uint16(n)
}

// securityInputs are the evaluation inputs of cfg's servers: kind, the BMC address and
// port (what an accepted risk binds to), minimum known good firmware and console setup.
// The runtime replaces them on every apply.
func securityInputs(cfg config.Config) map[string]bmcsec.Inputs {
	out := make(map[string]bmcsec.Inputs, len(cfg.Servers))
	for _, s := range cfg.Servers {
		vnc := s.Console.Graphical == config.GraphicalVNC
		out[s.ID] = bmcsec.Inputs{Kind: string(s.BMC.Kind), Address: net.JoinHostPort(s.BMC.Address, strconv.Itoa(s.BMC.Port)),
			MinFirmware: cfg.Security.MinFirmware.For(s.BMC.Kind),
			VNC:         vnc, VNCTLS: vnc && s.Console.VNC.TLSEnabled(), SerialSSH: s.Console.Serial == config.SerialBMCSSH}
	}
	return out
}

// securityInput is server id's evaluation inputs (bmcsec.Config.Inputs).
func (rt *serverRuntime) securityInput(id string) (bmcsec.Inputs, bool) {
	m := rt.inputs.Load()
	if m == nil {
		return bmcsec.Inputs{}, false
	}
	in, ok := (*m)[id]
	return in, ok
}

// serverName names a polled server in notifications.
func (rt *serverRuntime) serverName(id string) string {
	if s, ok := rt.fleet.Server(id); ok {
		return s.Name
	}
	return id
}

// buildSecurity builds the security check service over the runtime's fleet, or nil when
// security.enabled is false. Its notifications go through n (nil: none sent).
func buildSecurity(ctx context.Context, cfg config.Config, c *core, rt *serverRuntime, n *notify.Service,
	log *slog.Logger) (*bmcsec.Service, error) {
	if !cfg.Security.On() {
		return nil, nil
	}
	sc := bmcsec.Config{DB: c.db, Audit: c.audit, Fleet: rt.fleet, Inputs: rt.securityInput, Rerun: rt.fleet.RequestPosture,
		ServerName: rt.serverName, Logger: log}
	if n != nil {
		sc.Emit = n.Emit
	}
	return bmcsec.New(ctx, sc)
}

// securityCounts adapts the check counts for /metrics: an evaluation of each server's
// last posture, never a BMC request. nil without the service.
func securityCounts(s *bmcsec.Service) func(string) (metrics.SecurityCounts, bool) {
	if s == nil {
		return nil
	}
	return func(id string) (metrics.SecurityCounts, bool) {
		r, ok := s.Report(id)
		if !ok {
			return metrics.SecurityCounts{}, false
		}
		n := r.Counts()
		return metrics.SecurityCounts{Pass: n.Pass, Info: n.Info, Warn: n.Warn, Fail: n.Fail, Unknown: n.Unknown,
			CantRead: n.CantRead, Accepted: n.Accepted}, true
	}
}

// uiSecurity keeps a nil *bmcsec.Service a nil interface (the UI then hides the Security
// tab and the fleet column).
func uiSecurity(s *bmcsec.Service) ui.Security {
	if s == nil {
		return nil
	}
	return s
}

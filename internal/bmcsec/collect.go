package bmcsec

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/secprobe"
)

// Target is what Collect needs about one server. Every value comes from the validated
// config or the server registry; ports the BMC reports are only used on its own
// configured address.
type Target struct {
	Addr      netip.Addr
	HTTPSPort uint16 // the Redfish port the app polls
	Pin       []byte // SHA-256 of the pinned SPKI
	// VNC is the graphical console's VNC port when it runs over TLS (nil: not probed).
	VNC *VNCTarget
	// SSHPort is console.ssh.port when the serial console uses the BMC's SSH; 0 uses
	// the port the BMC reports, else 22.
	SSHPort uint16
	// ConsoleActive reports an open graphical console: the VNC port is then left alone
	// until the next run (the BMC takes one VNC session).
	ConsoleActive func() bool
}

// VNCTarget is the VNC port to probe.
type VNCTarget struct {
	Port           uint16
	Pin            []byte
	RSAKeyExchange bool // quirk idrac8_rsa_kex_tls
	// NotProbed, when set, is why the port is left alone (NotProbedIDRAC8); its check
	// then reads "Not checked" with this reason.
	NotProbed string
}

// NotProbedIDRAC8 is why the checks never open an iDRAC8's VNC port. Its VNC server
// takes one client at a time and stays busy for minutes after a connection ends: on
// fw 2.86 every handshake hung for 35 s after one had completed, while the web port
// answered in under a second. A probe there would lock the graphical console out, and
// would collide with the console's own probe, which runs on the same 6-hour tier. The
// port presents the web server's certificate, which the web checks cover and the
// console's probe holds to the pin.
const NotProbedIDRAC8 = "an iDRAC8 takes one VNC client at a time and stays busy for minutes after each connection, " +
	"so the checks leave this port to the console. The port presents the web certificate, which the web checks cover"

// Collector reads one server's posture; its probe options are shared by every server.
type Collector struct {
	Probe secprobe.Options
	Now   func() time.Time
}

func (c Collector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Collect reads the posture with d (the poller's own driver, so the run shares its
// Redfish session): the Redfish read first, then the handshake-only probes. It fails
// when the Redfish read fails as a whole, or when the run's context ended before the
// probes were done (a posture with holes from a deadline is no posture); a probe that
// fails within the budget is part of the posture (bmc.Posture.TransportFailure tells
// the fleet whether to trust it).
func (c Collector) Collect(ctx context.Context, d bmc.Driver, t Target) (bmc.Posture, error) {
	p := bmc.Posture{Started: c.now()}
	pr, ok := d.(bmc.PostureReader)
	if !ok {
		return bmc.Posture{}, fmt.Errorf("security checks: %w", bmc.ErrUnsupported)
	}
	rf, err := pr.Posture(ctx)
	if err != nil {
		return bmc.Posture{}, err
	}
	p.Redfish = rf
	web := netip.AddrPortFrom(t.Addr, t.HTTPSPort)
	p.Web = secprobe.ScanTLS(ctx, secprobe.TLSTarget{Addr: web, Pin: t.Pin}, c.Probe)
	p.VNC = c.vnc(ctx, t, rf.Protocols)
	p.SSH = c.ssh(ctx, t, rf.Protocols)
	p.HTTP = c.http(ctx, t, rf.Protocols)
	if p.Web.Usable() {
		p.WSMan = secprobe.CheckWSMan(ctx, web, t.Pin, c.Probe)
	} else {
		p.WSMan.Read = bmc.Skipped("the HTTPS port did not present the pinned certificate")
	}
	if err := ctx.Err(); err != nil {
		return bmc.Posture{}, fmt.Errorf("security checks: the run was cut short: %w", err)
	}
	p.Duration = c.now().Sub(p.Started)
	return p, nil
}

// vnc probes the VNC port, unless the console is not VNC over TLS, the BMC reports its
// VNC server off (nothing listens: a service the BMC reports off is not probed), the
// target says to leave the port alone (an iDRAC8: NotProbedIDRAC8), or a
// graphical console session is open.
func (c Collector) vnc(ctx context.Context, t Target, pr bmc.ProtocolFacts) bmc.TLSProbe {
	switch {
	case t.VNC == nil:
		return bmc.TLSProbe{}
	case pr.VNC.Known && !pr.VNC.Value:
		return bmc.TLSProbe{Read: bmc.Skipped("the BMC reports its VNC server off"), Port: int(t.VNC.Port)}
	case t.VNC.NotProbed != "":
		return bmc.TLSProbe{Read: bmc.Skipped(t.VNC.NotProbed), Port: int(t.VNC.Port)}
	case t.ConsoleActive != nil && t.ConsoleActive():
		return bmc.TLSProbe{Read: bmc.Skipped("a graphical console session was open"), Port: int(t.VNC.Port)}
	default:
		return secprobe.ScanTLS(ctx, vncProbeTarget(t), c.Probe)
	}
}

// consoleOpened is why a VNC probe stops when a graphical console session starts.
const consoleOpened = "a graphical console session was opened"

// vncProbeTarget is the VNC port as the probe sees it: the certificate only (one
// handshake; the version and suite checks apply to the web port, and the BMC takes one
// VNC client at a time), stopped before any further handshake if a console session has
// opened meanwhile.
func vncProbeTarget(t Target) secprobe.TLSTarget {
	pt := secprobe.TLSTarget{Addr: netip.AddrPortFrom(t.Addr, t.VNC.Port), Pin: t.VNC.Pin, RSAKeyExchange: t.VNC.RSAKeyExchange,
		IdentityOnly: true, Abort: func() string { return "" }}
	if active := t.ConsoleActive; active != nil {
		pt.Abort = func() string {
			if active() {
				return consoleOpened
			}
			return ""
		}
	}
	return pt
}

func (c Collector) ssh(ctx context.Context, t Target, pr bmc.ProtocolFacts) bmc.SSHProbe {
	port, ok := sshPort(t, pr)
	switch {
	case !ok:
		return bmc.SSHProbe{Read: bmc.Skipped("SSH is off")}
	case leftAlone(t, port):
		return bmc.SSHProbe{Read: bmc.Skipped(onVNCPort), Port: int(port)}
	}
	return secprobe.ScanSSH(ctx, netip.AddrPortFrom(t.Addr, port), c.Probe)
}

func (c Collector) http(ctx context.Context, t Target, pr bmc.ProtocolFacts) bmc.HTTPProbe {
	port, ok := httpPort(pr)
	switch {
	case !ok:
		return bmc.HTTPProbe{Read: bmc.Skipped("plain HTTP is off")}
	case leftAlone(t, port):
		return bmc.HTTPProbe{Read: bmc.Skipped(onVNCPort), Port: int(port)}
	}
	return secprobe.CheckHTTP(ctx, netip.AddrPortFrom(t.Addr, port), c.Probe)
}

// onVNCPort is why a probe whose port the BMC reports as its VNC port is not sent.
const onVNCPort = "the BMC reports this service on its VNC port, which the checks leave alone"

// leftAlone reports whether port is a VNC port the checks must not open (NotProbed): a
// port the BMC reports for another service must not get around that.
func leftAlone(t Target, port uint16) bool {
	return t.VNC != nil && t.VNC.NotProbed != "" && port == t.VNC.Port
}

// sshPort: none when the BMC reports SSH off; else the configured serial SSH port, the
// port the BMC reports, or 22.
func sshPort(t Target, pr bmc.ProtocolFacts) (uint16, bool) {
	switch {
	case pr.SSH.Known && !pr.SSH.Value:
		return 0, false
	case t.SSHPort != 0:
		return t.SSHPort, true
	default:
		return reportedPort(pr.SSHPort, 22), true
	}
}

func httpPort(pr bmc.ProtocolFacts) (uint16, bool) {
	if pr.HTTP.Known && !pr.HTTP.Value {
		return 0, false
	}
	return reportedPort(pr.HTTPPort, 80), true
}

func reportedPort(f bmc.Fact[int], def uint16) uint16 {
	if !f.Known || f.Value < 1 || f.Value > math.MaxUint16 {
		return def
	}
	return uint16(f.Value)
}

package main

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"oob-manager/internal/config"
	"oob-manager/internal/integrations"
	"oob-manager/internal/notify"
)

// buildIntegrations builds the GELF audit shipping service (Settings → Integrations,
// tech_doc §34) over the effective settings and installs its shipper in the audit
// logger's switch. runServer runs it. dial is the env.gelfDial test hook (nil:
// net.Dialer); the destination policy wraps it either way.
func (c *core) buildIntegrations(dial integrations.DialFunc) error {
	pol := integrations.Policy{Allowed: c.cfg.GELFNetworks(), Deny: c.bmcAddrs,
		Self: integrations.SelfEndpoints(append(selfAddrs(c.cfg), publicURLAddrs(c.cfg.PublicURL)...), selfPorts(c.cfg))}
	svc, err := integrations.New(integrations.Config{Settings: c.settings, Audit: c.audit, Switch: c.gelf, Policy: pol,
		Dial: dial, Logger: c.log, OnTrust: c.notifyTap.shipperTrust})
	if err != nil {
		return err
	}
	c.integrations = svc
	return nil
}

// publicURLAddrs resolves a public_url host name once at startup (a literal is already in
// selfAddrs): the address people type is often the Docker host's, which a bridge
// container does not see among its own interfaces.
func publicURLAddrs(publicURL string) []netip.Addr {
	u, err := url.Parse(publicURL)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	if _, perr := netip.ParseAddr(u.Hostname()); perr == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", u.Hostname())
	if err != nil {
		return nil
	}
	return addrs
}

// bmcAddrs lists the BMC addresses of the effective server registry (every entry,
// disabled and shadowed ones too): the GELF policy never dials them. Empty until serve
// has opened the registry.
func (c *core) bmcAddrs() []netip.Addr {
	reg := c.registry.Load()
	if reg == nil {
		return c.storedBMCAddrs()
	}
	var out []netip.Addr
	for _, e := range reg.Current().Entries() {
		if a, err := netip.ParseAddr(e.Server.BMC.Address); err == nil {
			out = append(out, a)
		}
	}
	return out
}

// storedBMCAddrs is the deny set before (or without) the registry: the BMC addresses of
// config.yaml's servers and of every browser-managed row, read directly. The CLI commands
// ship audit rows without opening the registry (opening it audits shadowed rows), and
// must still never dial a BMC. A row that cannot be read leaves only the file's servers.
func (c *core) storedBMCAddrs() []netip.Addr {
	var out []netip.Addr
	add := func(s string) {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	for _, s := range c.cfg.Servers {
		add(s.BMC.Address)
	}
	if c.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		rows, err := c.db.Servers().All(ctx)
		if err == nil {
			for _, r := range rows {
				add(r.Address)
			}
		} else if c.log != nil {
			c.log.Warn("GELF policy: browser-managed BMC addresses could not be read", "error", err)
		}
	}
	return out
}

// selfPorts are the ports the app listens on: the listen port and the public_url port
// (443 when https names none). A GELF address on one of them at one of the app's own
// addresses is refused.
func selfPorts(cfg config.Config) []uint16 {
	var out []uint16
	if _, p, err := net.SplitHostPort(cfg.Listen); err == nil {
		if n, perr := strconv.ParseUint(p, 10, 16); perr == nil {
			out = append(out, uint16(n))
		}
	}
	if u, err := url.Parse(cfg.PublicURL); err == nil && u.Host != "" {
		p := u.Port()
		if p == "" {
			p = "443"
		}
		if n, perr := strconv.ParseUint(p, 10, 16); perr == nil {
			out = append(out, uint16(n))
		}
	}
	return out
}

// shipperTrust turns the shipper's certificate check into a trust notification once the
// notifications service exists (a no-op before).
func (l *lateTap) shipperTrust(c integrations.TrustChange) {
	if s := l.svc.Load(); s != nil {
		s.Emit(notify.ShipperTrustEvent(shipperTrustKind(c), time.Now()))
	}
}

func shipperTrustKind(c integrations.TrustChange) notify.ShipperTrust {
	switch c {
	case integrations.TrustExpired:
		return notify.ShipperExpired
	case integrations.TrustResolved:
		return notify.ShipperResolved
	case integrations.TrustWithdrawn:
		return notify.ShipperWithdrawn
	default:
		return notify.ShipperMismatch
	}
}

// prepareServe applies the env test hooks, builds GELF shipping (so rows recorded from
// here on are queued for it) and verifies the audit chain.
func (c *core) prepareServe(e env) error {
	c.stepUpOverride = e.stepUpWindow
	if err := c.buildIntegrations(e.gelfDial); err != nil {
		return err
	}
	c.verifyAudit(e.ctx)
	return nil
}

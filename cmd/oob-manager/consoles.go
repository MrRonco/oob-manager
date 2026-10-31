package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"

	"oob-manager/internal/bmc/dellredfish"
	"oob-manager/internal/bmc/redfish"
	"oob-manager/internal/config"
	"oob-manager/internal/console"
	"oob-manager/internal/secrets"
)

// buildConsoles builds the graphical console broker (servers with console.graphical
// vnc) and the iDRAC native console launcher (Dell servers with an operator login).
// A missing VNC or operator credential is not fatal: the server page then says what
// to set up.
func buildConsoles(cfg config.Config, creds credLookup, aud console.Auditor, e env,
	log *slog.Logger) (*console.Service, *kvmLauncher, error) {
	targets, err := consoleTargets(cfg, creds, log)
	if err != nil {
		return nil, nil, err
	}
	svc, err := console.New(console.Config{Targets: targets, Audit: aud, Logger: log, Dial: e.vncDial,
		IdleTimeout: cfg.Console.IdleTimeout, MaxSession: cfg.Console.MaxSession})
	if err != nil {
		return nil, nil, err
	}
	return svc, newKVMLauncher(cfg, creds, e.kvmEndpoint, log), nil
}

// consoleTargets builds the graphical console targets of cfg's servers.
func consoleTargets(cfg config.Config, creds credLookup, log *slog.Logger) ([]console.Target, error) {
	var targets []console.Target
	for _, s := range cfg.Servers {
		if s.Console.Graphical != config.GraphicalVNC {
			continue
		}
		pw := vncPassword(s, creds, log)
		t, err := console.TargetFor(s, pw)
		if err != nil {
			return nil, err
		}
		if t.TLS && t.RSAKeyExchange {
			log.Warn("VNC console TLS allows RSA key exchange (quirk idrac8_rsa_kex_tls): no forward secrecy on the VNC port",
				"server", s.ID)
		}
		targets = append(targets, t)
	}
	return targets, nil
}

func vncPassword(s config.Server, creds credLookup, log *slog.Logger) secrets.Secret {
	c, err := creds.Lookup(s.Credentials.VNC)
	if err != nil {
		log.Warn("graphical console needs setup: VNC credential missing", "server", s.ID, "ref", s.Credentials.VNC)
		return secrets.Secret{}
	}
	for _, w := range console.PasswordWarnings(s.BMC.Kind, c.Password) {
		log.Warn("VNC password check", "server", s.ID, "warning", w)
	}
	if !s.Console.VNC.TLSEnabled() {
		log.Warn("VNC console without TLS: screen, keystrokes and the VNC challenge cross the network in clear",
			"server", s.ID)
	}
	return c.Password
}

// kvmLauncher opens iDRAC9's own HTML5 console (GetKVMSession) with the operator login.
// Its targets are replaced when the server registry changes.
type kvmLauncher struct {
	targets atomic.Pointer[map[string]kvmTarget]
}

type kvmTarget struct {
	cfg  redfish.Config
	host string // the BMC address the browser opens
}

func newKVMLauncher(cfg config.Config, creds credLookup, endpoint func(config.Server) string,
	log *slog.Logger) *kvmLauncher {
	k := &kvmLauncher{}
	k.set(kvmTargets(cfg, creds, endpoint, log))
	return k
}

func (k *kvmLauncher) set(t map[string]kvmTarget) { k.targets.Store(&t) }

// kvmTargets are the native console launch targets of cfg's servers.
func kvmTargets(cfg config.Config, creds credLookup, endpoint func(config.Server) string,
	log *slog.Logger) map[string]kvmTarget {
	if endpoint == nil {
		endpoint = defaultEndpoint
	}
	out := map[string]kvmTarget{}
	for _, s := range cfg.Servers {
		dell := s.BMC.Kind == config.KindIDRAC8 || s.BMC.Kind == config.KindIDRAC9
		if !dell || s.Credentials.Operator == "" {
			continue
		}
		op, err := creds.Lookup(s.Credentials.Operator)
		if err != nil || !op.HasLogin() {
			log.Warn("native console launch unavailable: operator credential missing", "server", s.ID)
			continue
		}
		out[s.ID] = kvmTarget{host: s.BMC.Address, cfg: redfish.Config{Endpoint: endpoint(s),
			Username: op.Username, Password: op.Password.Reveal(), PinSHA256: s.TLSPinSHA256,
			Timeout: s.BMC.Timeouts.Request, Auth: redfish.AuthMode(s.BMC.Auth)}}
	}
	return out
}

func defaultEndpoint(s config.Server) string { return s.BMC.Endpoint() }

// Available reports whether server id has an operator login for the launch.
func (k *kvmLauncher) Available(id string) bool {
	_, ok := (*k.targets.Load())[id]
	return ok
}

// Launch returns the one-time console URL (a Secret: it carries a temporary login).
func (k *kvmLauncher) Launch(ctx context.Context, id string) (secrets.Secret, error) {
	t, ok := (*k.targets.Load())[id]
	if !ok {
		return secrets.Secret{}, fmt.Errorf("kvm launch: server %s: not configured", id)
	}
	return dellredfish.LaunchKVM(ctx, t.cfg, t.host)
}

// bmcWebURL is the BMC web UI address for the "open the BMC web interface" link.
func bmcWebURL(cfg config.Config) func(id string) string {
	urls := map[string]string{}
	for _, s := range cfg.Servers {
		if s.BMC.Kind != config.KindIPMI {
			urls[s.ID] = s.BMC.Endpoint() + "/"
		}
	}
	return func(id string) string { return urls[id] }
}

package main

import (
	"log/slog"

	"oob-manager/internal/config"
	"oob-manager/internal/console"
	"oob-manager/internal/secrets"
)

// buildSerial builds the serial console broker for servers with console.serial bmcssh
// or sol. A missing operator credential or ssh_host_key is not fatal: the server page
// then says what to set up. Every server that uses the idrac8_legacy_ssh quirk is
// logged at startup, because it enables SHA-1 algorithms for that BMC.
func buildSerial(cfg config.Config, creds credLookup, aud console.Auditor, e env,
	log *slog.Logger) (*console.SerialService, error) {
	targets, err := serialTargets(cfg, creds, log)
	if err != nil {
		return nil, err
	}
	return console.NewSerial(console.SerialConfig{Targets: targets, Audit: aud, Logger: log, Dial: e.sshDial,
		IdleTimeout: cfg.Console.IdleTimeout, MaxSession: cfg.Console.MaxSession})
}

// serialTargets builds the serial console targets of cfg's servers.
func serialTargets(cfg config.Config, creds credLookup, log *slog.Logger) ([]console.SerialTarget, error) {
	var targets []console.SerialTarget
	for _, s := range cfg.Servers {
		if s.Console.Serial == config.SerialNone {
			continue
		}
		t, err := console.SerialTargetFor(s, serialLogin(s, creds, log))
		if err != nil {
			return nil, err
		}
		warnSerial(s, log)
		targets = append(targets, t)
	}
	return targets, nil
}

func serialLogin(s config.Server, creds credLookup, log *slog.Logger) secrets.Credential {
	op, err := creds.Lookup(s.Credentials.Operator)
	if err != nil || !op.HasLogin() {
		log.Warn("serial console needs setup: operator credential missing", "server", s.ID, "ref", s.Credentials.Operator)
		return secrets.Credential{}
	}
	return op
}

func warnSerial(s config.Server, log *slog.Logger) {
	switch {
	case s.Console.Serial == config.SerialSOL:
		log.Warn("serial console: IPMI SOL is not implemented yet; the server page shows it as unsupported", "server", s.ID)
	case s.SSHHostKey == "":
		log.Warn("serial console needs setup: ssh_host_key is not configured", "server", s.ID)
	}
	if s.Console.Serial == config.SerialBMCSSH && s.Console.SSH.Has(config.QuirkIDRAC8LegacySSH) {
		log.Warn("serial console SSH allows legacy algorithms (quirk idrac8_legacy_ssh): ssh-rsa (SHA-1) host key signatures and diffie-hellman-group14-sha1",
			"server", s.ID)
	}
}

package config

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Limits enforced by validation.
const (
	// PollFloor is the hard minimum poll interval: iDRAC session tables are tiny (D4).
	PollFloor = 30 * time.Second
)

// ValidationError lists every problem found, so one restart fixes them all.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	return "config: invalid:\n  - " + strings.Join(e.Problems, "\n  - ")
}

// problems is an append-only accumulator; add returns a new slice.
type problems []string

func (p problems) add(format string, args ...any) problems {
	return append(p, fmt.Sprintf(format, args...))
}

// Validate checks a fully defaulted Config. It does not modify cfg.
func Validate(cfg Config) error {
	var p problems
	p = validateListen(p, cfg.Listen)
	p = validateTLS(p, cfg.TLS)
	p = validatePublicURL(p, cfg.PublicURL)
	p = validateAuth(p, cfg.Auth)
	p = validateAudit(p, cfg.Audit)
	p = validatePoll(p, cfg.Poll)
	p = validatePaths(p, map[string]string{
		"storage.db_path":          cfg.Storage.DBPath,
		"storage.lease_dir":        cfg.Storage.LeaseDir,
		"secrets.credentials_file": cfg.Secrets.CredentialsFile,
		"secrets.identity_file":    cfg.Secrets.IdentityFile,
		"secrets.app_keys_file":    cfg.Secrets.AppKeysFile,
	})
	p = validateConsoleSettings(p, cfg.Console)
	p = append(p, ValidateGeneral(cfg.General(), cfg.Poll.MinInterval)...)
	p = validateSettings(p, cfg.Settings)
	p = validateServers(p, cfg.Servers)
	p = validateNotifications(p, cfg.Notifications)
	p = validateMetrics(p, cfg.Metrics)
	p = validateSecurity(p, cfg.Security)
	p = validateFirmware(p, cfg.Firmware)
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

func validateListen(p problems, listen string) problems {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return p.add("listen %q: %v", listen, err)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return p.add("listen %q: invalid port", listen)
	}
	return p
}

// validateTLS accepts both files or neither (the data-volume pair, plan 09), never one.
func validateTLS(p problems, t TLSConfig) problems {
	if t.CertFile == "" && t.KeyFile == "" {
		return p
	}
	return validatePaths(p, map[string]string{"tls.cert_file": t.CertFile, "tls.key_file": t.KeyFile})
}

func validatePaths(p problems, paths map[string]string) problems {
	for _, key := range sortedKeys(paths) {
		v := paths[key]
		switch {
		case v == "":
			p = p.add("%s is required", key)
		case !filepath.IsAbs(v):
			p = p.add("%s %q must be an absolute path", key, v)
		}
	}
	return p
}

// validatePublicURL accepts an empty value: links then use the request's host and
// CrossOriginProtection keeps its same-origin check (plan 09).
func validatePublicURL(p problems, raw string) problems {
	if raw == "" {
		return p
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return p.add("public_url %q must be an absolute https URL", raw)
	}
	return p
}

func validateAuth(p problems, a AuthConfig) problems {
	switch a.Mode {
	case AuthLocal:
	case AuthCFAccessLocal:
		if a.CFAccess.TeamDomain == "" || a.CFAccess.AUD == "" {
			p = p.add("auth.cfaccess.team_domain and auth.cfaccess.aud are required in mode %s", a.Mode)
		}
	default:
		p = p.add("auth.mode %q must be one of local, cfaccess+local", a.Mode)
	}
	return p
}

func validatePoll(p problems, c PollConfig) problems {
	if c.MinInterval < PollFloor {
		p = p.add("poll.min_interval %v is below the %v floor", c.MinInterval, PollFloor)
	}
	return p
}

func validateServers(p problems, servers []Server) problems {
	ids := map[string]bool{}
	names := map[string]bool{}
	for i, s := range servers {
		prefix := fmt.Sprintf("servers[%d] (%s)", i, s.ID)
		if ids[s.ID] {
			p = p.add("%s: duplicate id", prefix)
		}
		if names[s.Name] {
			p = p.add("%s: duplicate name %q", prefix, s.Name)
		}
		ids[s.ID], names[s.Name] = true, true
		p = validateServer(p, prefix, s)
	}
	return p
}

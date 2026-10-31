package config

import (
	"strings"
	"testing"
	"time"
)

func TestBMCAuthAndTimeoutDefaultsPerKind(t *testing.T) {
	cfg := mustParse(t, validYAML())
	r730, _ := cfg.Server("r730xd")
	r240, _ := cfg.Server("r240")
	if r730.BMC.Auth != BMCAuthSession || r240.BMC.Auth != BMCAuthSession {
		t.Fatalf("auth defaults %q %q", r730.BMC.Auth, r240.BMC.Auth)
	}
	if r730.BMC.Timeouts != (BMCTimeouts{Request: 30 * time.Second, Cycle: 150 * time.Second}) {
		t.Fatalf("idrac8 timeouts %+v", r730.BMC.Timeouts)
	}
	if r240.BMC.Timeouts != (BMCTimeouts{Request: 15 * time.Second, Cycle: 60 * time.Second}) {
		t.Fatalf("idrac9 timeouts %+v", r240.BMC.Timeouts)
	}
	if got := cfg.PollInterval(r730); got != 150*time.Second {
		t.Fatalf("interval must be raised to the idrac8 cycle timeout, got %v", got)
	}
	if got := cfg.PollInterval(r240); got != 60*time.Second {
		t.Fatalf("idrac9 interval %v", got)
	}
}

func TestBMCOverrides(t *testing.T) {
	src := strings.Replace(validYAML(), "kind: idrac9 }",
		"kind: idrac9, auth: basic, timeouts: { request: 20s, cycle: 90s } }", 1)
	r240, _ := mustParse(t, src).Server("r240")
	if r240.BMC.Auth != BMCAuthBasic || r240.BMC.Timeouts != (BMCTimeouts{Request: 20 * time.Second, Cycle: 90 * time.Second}) {
		t.Fatalf("overrides %+v", r240.BMC)
	}
	partial := strings.Replace(validYAML(), "kind: idrac8 }",
		"kind: idrac8, timeouts: { request: 45s } }", 1)
	r730, _ := mustParse(t, partial).Server("r730xd")
	if r730.BMC.Timeouts != (BMCTimeouts{Request: 45 * time.Second, Cycle: 150 * time.Second}) {
		t.Fatalf("a partial override keeps the other default: %+v", r730.BMC.Timeouts)
	}
}

func TestBMCValidation(t *testing.T) {
	const from = "kind: idrac9 }"
	for name, c := range map[string]struct{ to, want string }{
		"bad auth":          {"kind: idrac9, auth: digest }", "bmc.auth"},
		"request too short": {"kind: idrac9, timeouts: { request: 1s } }", "bmc.timeouts.request"},
		"request too long":  {"kind: idrac9, timeouts: { request: 5m } }", "bmc.timeouts.request"},
		"cycle too long":    {"kind: idrac9, timeouts: { cycle: 1h } }", "bmc.timeouts.cycle"},
		"cycle < request":   {"kind: idrac9, timeouts: { request: 60s, cycle: 30s } }", "bmc.timeouts.cycle"},
		"negative":          {"kind: idrac9, timeouts: { cycle: -1s } }", "bmc.timeouts.cycle"},
		"unknown key":       {"kind: idrac9, timeouts: { total: 1s } }", "total"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(strings.Replace(validYAML(), from, c.to, 1)))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v does not mention %q", err, c.want)
			}
		})
	}
}

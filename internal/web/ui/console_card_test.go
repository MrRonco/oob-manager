package ui

import (
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/console"
)

func capsView(gc, kvm bool, tier bmc.LicenseTier) ServerView {
	v := ServerView{ID: "r1", Name: "One", HasCapabilities: true,
		Capabilities: bmc.NewCapabilities(bmc.CapabilityParams{Flags: bmc.CapabilityFlags{GraphicalConsole: gc, KVMLaunch: kvm}})}
	if tier != "" {
		v.HasInventory = true
		v.Inventory = bmc.NewInventory(bmc.InventoryParams{License: bmc.License{Tier: tier}})
	}
	return v
}

func TestConsoleCardStates(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	ready := console.Status{Configured: true, HasPassword: true, TLS: true, Probe: console.Probe{State: console.ProbeOK}}
	cases := map[string]struct {
		v    ServerView
		st   console.Status
		want cardState
	}{
		"ready":            {capsView(true, false, bmc.LicenseEnterprise), ready, cardReady},
		"ready unprobed":   {capsView(true, false, ""), console.Status{Configured: true, HasPassword: true}, cardReady},
		"in use":           {capsView(true, false, ""), console.Status{Configured: true, HasPassword: true, InUse: true, Active: console.Active{Username: "bob", Since: now}}, cardInUse},
		"no password":      {capsView(true, false, ""), console.Status{Configured: true}, cardSetup},
		"vnc disabled":     {capsView(true, false, ""), console.Status{Configured: true, HasPassword: true, Probe: console.Probe{State: console.ProbeRefused}}, cardSetup},
		"pin mismatch":     {capsView(true, false, ""), console.Status{Configured: true, HasPassword: true, Probe: console.Probe{State: console.ProbePin}}, cardSetup},
		"tls mismatch":     {capsView(true, false, ""), console.Status{Configured: true, HasPassword: true, Probe: console.Probe{State: console.ProbeTLS}}, cardSetup},
		"unreachable":      {capsView(true, false, ""), console.Status{Configured: true, HasPassword: true, Probe: console.Probe{State: console.ProbeUnreached}}, cardSetup},
		"password refused": {capsView(true, false, ""), console.Status{Configured: true, HasPassword: true, RejectedAt: now}, cardSetup},
		"express licence":  {capsView(true, false, bmc.LicenseExpress), ready, cardLicense},
		"not configured":   {capsView(true, false, bmc.LicenseEnterprise), console.Status{}, cardSetup},
		"java only":        {capsView(false, false, ""), console.Status{}, cardUnsupported},
		"not probed":       {ServerView{ID: "r1"}, console.Status{}, cardUnknown},
		"native only":      {capsView(false, true, ""), console.Status{}, cardReady},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := buildConsoleCard(tc.v, tc.st, cardInput{kvm: tc.v.Capabilities.Flags().KVMLaunch, tf: fmtIn(time.UTC)})
			if c.State != tc.want {
				t.Fatalf("state = %q, want %q (%+v)", c.State, tc.want, c)
			}
			if c.Title == "" || c.Message == "" {
				t.Errorf("empty card text: %+v", c)
			}
		})
	}
	in := buildConsoleCard(capsView(true, false, ""), cases["in use"].st, cardInput{tf: fmtIn(time.UTC)})
	if in.ActiveUser != "bob" || in.ActiveSince == "" {
		t.Errorf("in-use card = %+v", in)
	}
	if c := buildConsoleCard(capsView(true, false, ""), ready, cardInput{tf: fmtIn(time.UTC)}); !c.OpenVNC || !c.TLS {
		t.Errorf("ready card = %+v", c)
	}
	if c := buildConsoleCard(capsView(false, true, ""), console.Status{}, cardInput{kvm: true, tf: fmtIn(time.UTC)}); c.OpenVNC || !c.KVM {
		t.Errorf("native-only card = %+v", c)
	}
}

func TestHumanDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{15 * time.Minute: "15 minutes", time.Minute: "1 minute",
		time.Hour: "1 hour", 4 * time.Hour: "4 hours", 90 * time.Minute: "90 minutes"} {
		if got := humanDuration(d); got != want {
			t.Errorf("%v: %q, want %q", d, got, want)
		}
	}
}

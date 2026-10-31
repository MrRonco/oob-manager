package power

import (
	"context"
	"errors"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

// TestSetTargets: a removed server's running verification stops (config_changed) and
// it can no longer be controlled; a changed server keeps its cooldown and gets its new
// confirm-page context at once.
func TestSetTargets(t *testing.T) {
	ctl := &fakeCtl{allowed: allResets, initial: bmc.PowerOn, states: []bmc.PowerState{bmc.PowerOn}}
	h := newHarness(t, ctl, func(c *Config) { c.GracefulTimeout = time.Hour })
	if err := h.svc.Request(context.Background(), "srv", GracefulShutdown, actor); err != nil {
		t.Fatal(err)
	}
	open := h.svc.targets.Load()
	cur := (*open)["srv"]
	cur.Impact, cur.SelfHost = []string{"Storage goes away"}, true
	if err := h.svc.SetTargets([]Target{cur}); err != nil {
		t.Fatal(err)
	}
	if in := h.svc.Info("srv"); !in.SelfHost || len(in.Impact) != 1 || h.svc.CooldownLeft("srv") == 0 {
		t.Fatalf("changed target: %+v cooldown %v", in, h.svc.CooldownLeft("srv"))
	}
	if op, _ := h.svc.Last("srv"); op.Phase != PhasePending {
		t.Fatalf("a changed server stopped its verification: %+v", op)
	}
	if err := h.svc.SetTargets(nil); err != nil {
		t.Fatal(err)
	}
	all := waitAudits(t, h.aud, 2)
	found := false
	for _, e := range all {
		found = found || e.ErrorClass == "config_changed"
	}
	if !found {
		t.Fatalf("no config_changed record: %+v", all)
	}
	if h.svc.Info("srv").Configured {
		t.Fatal("removed server still configured")
	}
	if err := h.svc.Request(context.Background(), "srv", On, actor); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("request after removal: %v", err)
	}
	if err := h.svc.SetTargets([]Target{{ServerID: "a"}, {ServerID: "a"}}); err == nil {
		t.Fatal("duplicate accepted")
	}
}

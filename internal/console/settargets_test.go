package console

import (
	"context"
	"errors"
	"testing"
	"time"

	"oob-manager/internal/bmc/bmcssh/sshtest"
	"oob-manager/internal/config"
	"oob-manager/internal/console/rfbtest"
	"oob-manager/internal/secrets"
)

func targetOf(t *testing.T, s config.Server, pw string) Target {
	t.Helper()
	tg, err := TargetFor(s, secrets.New(pw))
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

// TestSetTargetsEndsChangedAndRemovedConsoles: a running console on a server whose
// target changed (or that was removed) ends with reason config_changed; one on an
// unchanged server keeps running.
func TestSetTargetsEndsChangedAndRemovedConsoles(t *testing.T) {
	h := newHarness(t, config.KindIDRAC9, nil)
	b := h.open(false, nil)
	same := targetOf(t, serverCfg(config.KindIDRAC9, false, ""), rfbtest.Password)
	if err := h.svc.SetTargets([]Target{same}); err != nil {
		t.Fatal(err)
	}
	if !h.svc.Status("r1").InUse {
		t.Fatal("an unchanged target ended its console")
	}
	moved := serverCfg(config.KindIDRAC9, false, "")
	moved.BMC.Address = "192.0.2.20"
	if err := h.svc.SetTargets([]Target{targetOf(t, moved, rfbtest.Password)}); err != nil {
		t.Fatal(err)
	}
	if err := <-b.done; err != nil && !errors.Is(err, reasonConfigChanged) {
		t.Fatalf("serve: %v", err)
	}
	stop := h.audit.waitFor(t, "console.vnc.stop", 1)[0]
	if stop.Params["reason"] != "config_changed" {
		t.Fatalf("stop reason = %v", stop.Params["reason"])
	}
	if !h.svc.Status("r1").Configured {
		t.Fatal("changed target missing")
	}
	// Removed: not configured any more, and a new console is refused.
	if err := h.svc.SetTargets(nil); err != nil {
		t.Fatal(err)
	}
	if h.svc.Status("r1").Configured {
		t.Fatal("removed target still configured")
	}
	if _, err := h.svc.Issue(h.grant(false)); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("issue after removal: %v", err)
	}
	if err := h.svc.SetTargets([]Target{same, same}); err == nil {
		t.Fatal("duplicate accepted")
	}
}

func TestSetTargetsPasswordChangeEndsConsole(t *testing.T) {
	h := newHarness(t, config.KindIDRAC9, nil)
	b := h.open(false, nil)
	if err := h.svc.SetTargets([]Target{targetOf(t, serverCfg(config.KindIDRAC9, false, ""), "other-pw")}); err != nil {
		t.Fatal(err)
	}
	<-b.done
	if h.svc.Status("r1").InUse {
		t.Fatal("console kept after the VNC password changed")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// TestSerialSetTargets: a confirmed new host key (a changed target) ends the running
// serial console and clears the "host key changed" record; removal un-configures it.
func TestSerialSetTargets(t *testing.T) {
	h := newSerialHarness(t, sshtest.Options{}, nil)
	cur, _ := h.svc.target("r1")
	if err := h.svc.SetTargets([]SerialTarget{cur}); err != nil {
		t.Fatal(err)
	}
	h.svc.mu.Lock()
	h.svc.last["r1"] = SerialAttempt{Class: "host_key"}
	h.svc.mu.Unlock()
	if h.svc.Status("r1").Last.Class != "host_key" {
		t.Fatal("unchanged target dropped the last attempt")
	}
	changed := cur
	changed.SSH.HostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	if err := h.svc.SetTargets([]SerialTarget{changed}); err != nil {
		t.Fatal(err)
	}
	if st := h.svc.Status("r1"); st.Last.Class != "" || !st.HasHostKey {
		t.Fatalf("after a new host key: %+v", st)
	}
	if err := h.svc.SetTargets(nil); err != nil {
		t.Fatal(err)
	}
	if h.svc.Status("r1").Configured {
		t.Fatal("removed serial target still configured")
	}
	if err := h.svc.SetTargets([]SerialTarget{cur, cur}); err == nil {
		t.Fatal("duplicate accepted")
	}
}

func TestProbeBannerExported(t *testing.T) {
	fake := rfbtest.New(t, rfbtest.Options{})
	tg := targetOf(t, serverCfg(config.KindIDRAC9, false, ""), rfbtest.Password)
	p := ProbeBanner(context.Background(), redirect(fake.Addr()), tg, time.Unix(1, 0))
	if p.State != ProbeOK || p.Version == 0 {
		t.Fatalf("probe = %+v", p)
	}
	if st := fake.Stats(); st.AuthFailures != 0 || st.AuthOK != 0 {
		t.Fatal("the banner probe tried to authenticate")
	}
}

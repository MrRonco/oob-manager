package main

// repopolicy:allow private-addresses -- browser-added servers must sit inside the default bmc_networks, the RFC 1918 blocks

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/config"
	"oob-manager/internal/registry"
	"oob-manager/internal/secrets"
	"oob-manager/internal/secrets/credstore"
)

// TestRuntimeHotApplyRace adds, edits, disables and removes browser-managed servers
// from several goroutines while readers load the fleet, the consoles and the links;
// run with -race. Every change reaches the running services without a restart.
func TestRuntimeHotApplyRace(t *testing.T) {
	d := newDeployment(t, "")
	cfg, err := config.Load(d.configPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := openCore(ctx, cfg, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.close() }()
	reg, err := c.openRegistry(ctx)
	if err != nil {
		t.Fatal(err)
	}
	file, err := secrets.ParseCredentials([]byte("r240-ro: {username: " + redfishmock.User + ", password: " + redfishmock.Password + "}\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := env{ctx: ctx, newDriver: func(s config.Server, ro secrets.Credential) (bmc.Driver, error) {
		return bmcDriverAt(s, ro, d.mock.URL())
	}, kvmEndpoint: func(config.Server) string { return d.mock.URL() }}
	rt, err := newRuntime(ctx, cfg, c, reg, file, e, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	var bg sync.WaitGroup
	bg.Go(func() { rt.fleet.Run(ctx) })
	bg.Go(func() { rt.run(ctx) })
	readers, stop := startReaders(rt)

	a := admin.Actor{Username: "alice", Method: "local"}
	var writers sync.WaitGroup
	for w := range 3 {
		writers.Go(func() { churn(t, reg, a, fmt.Sprintf("hot%d", w), fmt.Sprintf("10.9.0.%d", 10+w), d.mock.PinSHA256()) })
	}
	writers.Wait()
	addServer(t, reg, a, "keep1", "10.9.1.10", d.mock.PinSHA256())
	waitUntil(t, "hot-added server polled", func() bool {
		s, ok := rt.fleet.Server("keep1")
		return ok && s.HasSnapshot
	})
	if rt.webURL("keep1") != "https://10.9.1.10:443/" || !rt.lifecycle("keep1") {
		t.Fatalf("links: %q %v", rt.webURL("keep1"), rt.lifecycle("keep1"))
	}
	// poll.interval applies live: the pollers are rebuilt with the new interval.
	if _, err = c.settings.UpdateGeneral(ctx, a, c.settings.Current().Rev, map[string]string{config.KeyPollInterval: "120"}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "new poll interval", func() bool {
		s, ok := rt.fleet.Server("keep1")
		return ok && s.Interval == 2*time.Minute
	})
	for _, s := range rt.fleet.Servers() {
		if strings.HasPrefix(s.ID, "hot") {
			t.Fatalf("removed server %s still polled", s.ID)
		}
	}
	close(stop)
	readers.Wait()
	cancel()
	bg.Wait()
}

func startReaders(rt *serverRuntime) (*sync.WaitGroup, chan struct{}) {
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, s := range rt.fleet.Servers() {
					_ = rt.cd.svc.Status(s.ID)
					_ = rt.cd.serial.Status(s.ID)
					_ = rt.cd.power.Info(s.ID)
					_ = rt.cd.kvm.Available(s.ID)
					_ = rt.webURL(s.ID)
					_, _ = rt.cd.fans.Policy(s.ID)
				}
			}
		})
	}
	return &wg, stop
}

func addServer(t *testing.T, reg *registry.Service, a admin.Actor, id, addr, pin string) {
	t.Helper()
	ctx := context.Background()
	_, err := reg.Create(ctx, a, registry.Draft{ID: id, Name: "Hot " + id, Kind: config.KindIDRAC9, Address: addr, Port: 443,
		TLSPin: pin, PinVia: "manual"})
	if err != nil {
		t.Error(err)
		return
	}
	x, _ := reg.Current().DBEntry(id)
	if _, err = reg.SetCredential(ctx, a, id, x.Rev, credstore.SlotReadOnly, redfishmock.User, redfishmock.Password); err != nil {
		t.Error(err)
		return
	}
	x, _ = reg.Current().DBEntry(id)
	if _, err = reg.SetEnabled(ctx, a, id, x.Rev, true); err != nil {
		t.Error(err)
	}
}

// churn adds a server, renames it, disables it and removes it.
func churn(t *testing.T, reg *registry.Service, a admin.Actor, id, addr, pin string) {
	ctx := context.Background()
	addServer(t, reg, a, id, addr, pin)
	x, _ := reg.Current().DBEntry(id)
	if _, err := reg.UpdateIdentity(ctx, a, id, x.Rev, "Renamed "+id, []string{"lab"}); err != nil {
		t.Error(err)
	}
	x, _ = reg.Current().DBEntry(id)
	if _, err := reg.SetEnabled(ctx, a, id, x.Rev, false); err != nil {
		t.Error(err)
	}
	x, _ = reg.Current().DBEntry(id)
	if err := reg.Delete(ctx, a, id, x.Rev); err != nil {
		t.Error(err)
	}
}

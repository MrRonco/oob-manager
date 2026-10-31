package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/config"
	"oob-manager/internal/firmware"
	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/firmware/catalog/catalogtest"
	"oob-manager/internal/firmware/catalog/dell"
	"oob-manager/internal/fwcatalog"
	"oob-manager/internal/fwinventory"
	"oob-manager/internal/secrets"
	"oob-manager/internal/store"
)

func TestFirmwarePolicyFromConfig(t *testing.T) {
	cfg := config.Config{
		Security: config.SecurityConfig{MinFirmware: config.MinFirmware{IDRAC8: "2.86.86.86"}},
		Firmware: config.FirmwareConfig{StaleAfter: "3y", Names: map[string]string{"101068": "Expander"},
			Minimum: []config.FirmwareRule{{BMCKind: "idrac8", Kind: "bios", Version: "2.20.0", Note: "fix"}}},
	}
	p := firmwarePolicy(cfg)
	if p.BMCMinimum("idrac8") != "2.86.86.86" || p.BMCMinimum("idrac9") != "" || p.StaleAfter() != 3*firmware.Year ||
		p.Name("101068") != "Expander" || len(p.Rules()) != 1 || p.Rules()[0].Note != "fix" {
		t.Fatalf("policy %+v", p)
	}
	srv := firmware.ServerInfo{BMCKind: "idrac8"}
	if v := p.Evaluate(srv, firmware.Component{Kind: bmc.FirmwareBMC, Running: "2.85.85.85"}, time.Now()); v.Primary() != firmware.FlagBelowMinimum ||
		v.MinimumSource != "security.min_firmware.idrac8" {
		t.Fatalf("the BMC minimum is security.min_firmware: %+v", v)
	}
}

func TestFirmwareSinkBeforeTheService(t *testing.T) {
	var s firmwareSink
	if s.Need("x", time.Now())(bmc.FirmwareItem{}) {
		t.Fatal("no service: no document reads")
	}
	if err := s.Record(context.Background(), "x", bmc.FirmwareScan{}, time.Now()); !errors.Is(err, errFirmwareNotReady) {
		t.Fatalf("record without the service: %v", err)
	}
	if uiFirmware(nil) != nil || apiFirmware(nil) != nil || firmwareCounts(nil) != nil {
		t.Fatal("a nil service is a nil interface")
	}
}

// TestFirmwareViewOverTheRuntime: the runtime's fleet scans the R240 mock's firmware into
// the view (names from the member documents), with GETs only, and a server that leaves
// the registry loses its rows.
func TestFirmwareViewOverTheRuntime(t *testing.T) {
	d := newDeployment(t, "")
	cfg, err := config.Load(d.configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Servers[0].TLSPinSHA256 = d.mock.PinSHA256() // the deployment pins a placeholder
	// The NIC's running (Installed-) member document is synthetic, kept apart from the
	// captured fixtures the deployment serves.
	const nicDoc = "UpdateService_FirmwareInventory_Installed-105897-23.31.1__NIC.Embedded.1-1-1.json"
	raw, err := os.ReadFile(filepath.Join(redfishmock.FixtureDir(t, filepath.Join("synthetic-firmware", "idrac9-r240")), nicDoc)) // #nosec G304 -- a test fixture
	if err != nil {
		t.Fatal(err)
	}
	d.mock.SetOverlay("/redfish/v1/UpdateService/FirmwareInventory/Installed-105897-23.31.1__NIC.Embedded.1-1-1", string(raw))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := openCore(ctx, cfg, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.close() }()
	// A server the registry does not know (removed from config.yaml while the app was down).
	ghost := store.FirmwareComponentRow{ServerID: "ghost", ComponentID: "159", Kind: "bios", Running: "1", FirstSeen: time.Now(),
		LastSeen: time.Now()}
	if err = c.db.Firmware().ReplaceServer(ctx, store.FirmwareScanRow{ServerID: "ghost", ScannedAt: time.Now()},
		[]store.FirmwareComponentRow{ghost}, nil); err != nil {
		t.Fatal(err)
	}
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
	svc, chk, err := buildFirmware(ctx, cfg, c, rt, nil, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if comps, _ := c.db.Firmware().Components(ctx); len(comps) != 0 {
		t.Fatalf("the ghost server's rows stayed: %+v", comps)
	}
	var bg sync.WaitGroup
	bg.Go(func() { rt.fleet.Run(ctx) })
	defer func() { cancel(); bg.Wait() }()
	waitUntil(t, "firmware scanned", func() bool {
		v, serr := svc.Server(ctx, "r240")
		return serr == nil && v.Scanned
	})
	v, _ := svc.Server(ctx, "r240")
	var nic firmware.Row
	for _, r := range v.Rows {
		if r.ComponentID == "105897" && r.FQDD == "NIC.Embedded.1-1-1" {
			nic = r
		}
	}
	if nic.Display != "Broadcom Gigabit Ethernet BCM5720 - 00:00:5E:00:53:00" || nic.ReleaseDate.IsZero() ||
		v.Info.BMCKind != "idrac9" || v.Scan.Listed != 25 {
		t.Fatalf("scan %+v nic %+v", v.Scan, nic)
	}
	if n, ok := firmwareCounts(svc)("r240"); !ok || n.Components != len(v.Rows) {
		t.Fatalf("counts %+v", n)
	}
	if v.Scan.SystemID != catalogtest.SystemIDNew || v.Coverage.State != firmware.CoverageNone {
		t.Fatalf("system id %q coverage %+v", v.Scan.SystemID, v.Coverage)
	}
	// A catalog import (here signed by the test key) turns on the update verdicts.
	key := catalogtest.RSAKey(t)
	src, err := dell.NewSource(key.PublicArmored(t))
	if err != nil {
		t.Fatal(err)
	}
	im := fwcatalog.Importer{Source: src, Repo: c.db.Catalog(), Dir: t.TempDir(), Limits: catalog.DefaultLimits(),
		Want: fwcatalog.FleetWant(c.db.Firmware(), nil)}
	data := catalogtest.Catalog()
	staged, err := fwcatalog.Stage(im.Dir, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := im.Import(ctx, fwcatalog.Input{Origin: fwcatalog.OriginCLI, File: staged, Sig: key.Sign(t, data)}); err != nil {
		t.Fatal(err)
	}
	chk.Invalidate()
	v, _ = svc.Server(ctx, "r240")
	states := map[string]firmware.UpdateState{}
	for _, r := range v.Rows {
		states[r.ComponentID] = r.Update.State
	}
	if states["159"] != firmware.UpdateAvailable || states["25227"] != firmware.UpdateUrgent || v.Coverage.Urgent != 1 {
		t.Fatalf("updates %v coverage %+v", states, v.Coverage)
	}
	if n := svc.WarnCount(ctx); n < 1 {
		t.Fatalf("the urgent update is not in the sidebar count: %d", n)
	}
	if d.mock.OtherWrites() != 0 {
		t.Fatalf("the firmware view wrote to the BMC: %+v", d.mock.Requests())
	}
	if err := svc.Rescan(ctx, admin.Actor{Username: "alice", Method: "local"}, "r240"); err != nil {
		t.Fatal(err)
	}
	if tab := svc.Table(ctx, firmware.Filter{}); tab.Total != len(v.Rows) {
		t.Fatalf("table %d rows", tab.Total)
	}
	firmwarePrune(svc, quietLog())(ctx) // the janitor's pass
	firmwarePrune(nil, quietLog())(ctx)
	if !errors.Is(svc.Rescan(ctx, admin.Actor{Username: "alice", Method: "local"}, "nope"), fwinventory.ErrNotFound) {
		t.Fatal("unknown server")
	}
}

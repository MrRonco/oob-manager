package main

import (
	"context"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"oob-manager/internal/config"
	"oob-manager/internal/store"
)

// TestBMCAddrsWithoutRegistry: a CLI command (no registry loaded) still denies every BMC
// address to the GELF shipper, from config.yaml's servers and the browser-managed rows,
// so a mis-set target can never make the CLI dial a BMC (review of H2, low 1).
func TestBMCAddrsWithoutRegistry(t *testing.T) {
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "oob.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC)
	if err := db.Servers().Insert(context.Background(), store.ServerRow{ID: "edge1", Name: "Edge", Tags: []string{},
		Kind: "idrac9", Address: "192.0.2.61", Port: 443, FanMode: "none", ConsoleSerial: "none",
		ConsoleGraphical: "none", VNCPort: 5901, SSHPort: 22, PowerImpact: []string{},
		CreatedAt: now, CreatedBy: "alice", UpdatedAt: now, UpdatedBy: "alice"}); err != nil {
		t.Fatal(err)
	}
	c := &core{db: db, cfg: config.Config{Servers: []config.Server{
		{ID: "r240", BMC: config.BMCConfig{Address: "192.0.2.72"}},
		{ID: "named", BMC: config.BMCConfig{Address: "bmc.example.test"}},
	}}}
	got := c.bmcAddrs()
	for _, want := range []string{"192.0.2.72", "192.0.2.61"} {
		if !slices.Contains(got, netip.MustParseAddr(want)) {
			t.Errorf("deny set %v lacks %s", got, want)
		}
	}
}

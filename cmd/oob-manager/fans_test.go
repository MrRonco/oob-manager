package main

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/config"
	"oob-manager/internal/fan"
	"oob-manager/internal/secrets"
	"oob-manager/internal/store"
)

func fanTestConfig(dir, pin string) config.Config {
	srv := func(id string, kind config.BMCKind, mode config.FanMode, op string) config.Server {
		return config.Server{ID: id, Name: id, BMC: config.BMCConfig{Address: "192.0.2.10", Kind: kind,
			Timeouts: config.BMCTimeouts{Request: 5 * time.Second}}, TLSPinSHA256: pin,
			Credentials: config.CredentialRef{ReadOnly: id + "-ro", Operator: op},
			Fan:         config.FanConfig{Mode: mode, SafeMinPct: 41, MaxLease: time.Hour}}
	}
	return config.Config{Storage: config.StorageConfig{LeaseDir: dir}, Servers: []config.Server{
		srv("host", config.KindIDRAC8, config.FanHostLease, "host-op"),
		srv("floor", config.KindIDRAC9, config.FanRedfishFloor, "floor-op"),
		srv("noop", config.KindIDRAC9, config.FanRedfishFloor, "missing-op"),
		srv("oem", config.KindIDRAC8, config.FanIPMIOEM, "host-op"),
		srv("none", config.KindRedfish, config.FanNone, ""),
	}}
}

func TestBuildFans(t *testing.T) {
	mock := redfishmock.New(t, redfishmock.FixtureDir(t, "idrac9-r240"), redfishmock.WithFanFloor())
	creds, err := secrets.ParseCredentials([]byte("host-op: {username: a, password: b}\nfloor-op: {username: " +
		redfishmock.OperatorUser + ", password: " + redfishmock.OperatorPassword + "}\n"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	db, err := store.Open(context.Background(), filepath.Join(dir, "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var logs bytes.Buffer
	svc, err := buildFans(fanTestConfig(dir, mock.PinSHA256()), db, creds, nopAudit{},
		func(config.Server) string { return mock.URL() }, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{"host": true, "floor": true, "noop": false, "oem": false, "none": false} {
		if _, ok := svc.Policy(id); ok != want {
			t.Errorf("%s: fan control = %v, want %v", id, ok, want)
		}
	}
	if !strings.Contains(logs.String(), "operator credential missing") || !strings.Contains(logs.String(), "ipmi-oem is not implemented") {
		t.Errorf("logs: %s", logs.String())
	}
	ctx := context.Background()
	if _, err := svc.Start(ctx, fan.Actor{Username: "op"}, "floor", fan.Request{Pct: 50, Duration: 30 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if err := svc.End(ctx, fan.Actor{Username: "op"}, "floor"); err != nil {
		t.Fatal(err)
	}
	if st := mock.FanFloorStats(); len(st.Patches) != 2 || st.Patches[0] != 50 || st.Patches[1] != redfishmock.FanFloorAuto {
		t.Fatalf("patches %+v", st)
	}
}

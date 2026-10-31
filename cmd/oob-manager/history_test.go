package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/config"
	"oob-manager/internal/history"
	"oob-manager/internal/secrets"
	"oob-manager/internal/store"
)

// TestHistoryOverTheRuntime: the runtime's fleet writes the R240 mock's readings into the
// history (the analog voltage rails included by default; this fixture reports no power
// draw), the read-only pool serves them,
// a server that left the registry loses its rows, the janitor's status reaches /metrics,
// and nothing is written to the BMC.
func TestHistoryOverTheRuntime(t *testing.T) {
	d := newDeployment(t, "")
	cfg, err := config.Load(d.configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Servers[0].TLSPinSHA256 = d.mock.PinSHA256()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := openCore(ctx, cfg, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.close() }()
	if _, err = c.db.History().Insert(ctx, store.SensorPoll{ServerID: "ghost", TS: time.Now().Add(-history.SyncGrace - time.Hour), Samples: []store.SensorSample{
		{Key: "temp:1", Kind: store.SensorTemp, Unit: store.UnitCelsius, Value: 40}}}); err != nil {
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
	svc, ro, err := openHistory(ctx, c, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	if err = rt.setHistory(ctx, svc); err != nil {
		t.Fatal(err)
	}
	if keys, _ := svc.Sensors(ctx, "ghost"); len(keys) != 0 {
		t.Fatalf("the ghost server's history stayed: %+v", keys)
	}
	if r := c.historyRetention(); r != (history.Retention{RawDays: 7, HourlyDays: 90, DailyDays: 730}) {
		t.Fatalf("retention %+v", r)
	}
	var bg sync.WaitGroup
	bg.Go(func() { rt.fleet.Run(ctx) })
	defer func() { cancel(); bg.Wait() }()
	waitUntil(t, "samples recorded", func() bool {
		keys, serr := svc.Sensors(ctx, "r240")
		return serr == nil && len(keys) > 3
	})
	keys, _ := svc.Sensors(ctx, "r240")
	kinds := map[store.SensorKind]bool{}
	for _, k := range keys {
		kinds[k.Kind] = true
	}
	if !kinds[store.SensorTemp] || !kinds[store.SensorFan] || !kinds[store.SensorVolt] || kinds[store.SensorPower] {
		t.Fatalf("kinds %v", kinds)
	}
	if err = svc.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if st := historyState(svc)(); !st.Ready || st.RawRows == 0 || st.DBBytes == 0 {
		t.Fatalf("metrics state %+v", st)
	}
	if historyState(nil) != nil || uiHistory(nil, nil) != nil || apiHistory(nil) != nil || uiHistory(svc, nil) == nil || uiHistory(svc, func() time.Time { return time.Unix(7, 0) }).Now().Unix() != 7 || apiHistory(svc) == nil {
		t.Fatal("a nil service is a nil interface")
	}
	if d.mock.OtherWrites() != 0 {
		t.Fatalf("the history wrote to the BMC: %+v", d.mock.Requests())
	}
}

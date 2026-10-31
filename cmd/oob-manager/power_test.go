package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/config"
	"oob-manager/internal/power"
	"oob-manager/internal/secrets"
)

func TestBuildPower(t *testing.T) {
	mock := redfishmock.New(t, redfishmock.FixtureDir(t, "idrac9-r240"), redfishmock.WithPowerControl(0))
	creds, err := secrets.ParseCredentials([]byte("r2-op: {username: " + redfishmock.OperatorUser +
		", password: " + redfishmock.OperatorPassword + "}\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := consoleTestConfig(mock.PinSHA256())
	cfg.Servers[1].Power = config.PowerConfig{SelfHost: true, Impact: []string{"Gateway"}}
	cfg.Servers[0].Credentials.Operator = "absent"
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	svc, err := buildPower(cfg, creds, nopAudit{}, func(config.Server) string { return mock.URL() }, nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Shutdown()
	if i := svc.Info("r1"); !i.Configured || i.Operator {
		t.Fatalf("r1 (operator credential missing) %+v", i)
	}
	if i := svc.Info("r2"); !i.Operator || !i.SelfHost || i.Impact[0] != "Gateway" {
		t.Fatalf("r2 %+v", i)
	}
	if i := svc.Info("r3"); !i.Configured || i.Operator {
		t.Fatalf("r3 (ipmi, no Redfish reset yet) %+v", i)
	}
	for _, want := range []string{"credential missing", "server=r1", "IPMI chassis control is not implemented", "server=r3"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, logs.String())
		}
	}
	err = svc.Request(context.Background(), "r2", power.ForceOff, power.Actor{Username: "u", Role: "admin", SrcIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for op, _ := svc.Last("r2"); !op.Final(); op, _ = svc.Last("r2") {
		if time.Now().After(deadline) {
			t.Fatal("verification did not finish")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if op, _ := svc.Last("r2"); op.Phase != power.PhaseDone || op.State != bmc.PowerOff {
		t.Fatalf("op %+v", op)
	}
	if st := mock.PowerStats(); len(st.Resets) != 1 || st.Resets[0] != "ForceOff" {
		t.Fatalf("mock %+v", st)
	}
}

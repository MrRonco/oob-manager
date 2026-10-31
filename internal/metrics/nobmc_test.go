package metrics

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
	"oob-manager/internal/store"
)

// countingDriver is a BMC that counts every call made to it.
type countingDriver struct{ calls atomic.Int64 }

func (d *countingDriver) Probe(context.Context) (bmc.Capabilities, error) {
	d.calls.Add(1)
	return bmc.Capabilities{}, nil
}

func (d *countingDriver) Snapshot(context.Context) (bmc.Snapshot, error) {
	d.calls.Add(1)
	return healthySnapshot(), nil
}

func (d *countingDriver) EventLog(context.Context, time.Time) (bmc.EventLog, error) {
	d.calls.Add(1)
	return bmc.NewEventLog("sel", nil, true), nil
}

func (d *countingDriver) Inventory(context.Context) (bmc.Inventory, error) {
	d.calls.Add(1)
	return bmc.Inventory{}, nil
}

type nopSamples struct{}

func (nopSamples) Insert(context.Context, store.SensorPoll) (store.InsertResult, error) {
	return store.InsertResult{}, nil
}
func (nopSamples) NoteClockJump(context.Context, time.Time) error { return nil }

type nopCaps struct{}

func (nopCaps) Put(context.Context, store.Capability) error { return nil }
func (nopCaps) Get(context.Context, string) (store.Capability, error) {
	return store.Capability{}, store.ErrNotFound
}

// TestScrapeNeverCallsTheBMC runs a real fleet against a counting driver: once the
// first poll is in, any number of scrapes adds no driver call.
func TestScrapeNeverCallsTheBMC(t *testing.T) {
	d := &countingDriver{}
	fl, err := fleet.New(fleet.Config{Targets: []fleet.Target{{ID: "s1", Name: "S1", Driver: d}},
		Samples: nopSamples{}, Capabilities: nopCaps{}, Interval: time.Hour, CycleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { fl.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if s, _ := fl.Server("s1"); s.HasSnapshot && s.HasInventory && s.HasSEL {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first poll never completed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	before := d.calls.Load()
	c, err := New(Config{Fleet: fl, CacheFor: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	for range 50 {
		body, err := c.Render(context.Background())
		if err != nil || !strings.Contains(string(body), `oob_server_up{server="s1"} 1`) {
			t.Fatalf("scrape: %v", err)
		}
	}
	if after := d.calls.Load(); after != before {
		t.Fatalf("scrapes made %d BMC calls", after-before)
	}
}

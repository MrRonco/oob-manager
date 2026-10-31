package fleet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/store"
)

func historySnapshot() bmc.Snapshot {
	return bmc.NewSnapshot(bmc.SnapshotParams{TakenAt: t0, Health: bmc.HealthOK,
		Temperatures: []bmc.Temperature{{ID: "t1", Name: "Inlet", Celsius: bmc.ReadingOf(22)},
			{ID: "t1", Name: "dup", Celsius: bmc.ReadingOf(99)}, {ID: "t2", Name: "CPU1"}},
		Fans: []bmc.Fan{{Name: "Fan 1", Speed: bmc.ReadingOf(7000), Units: bmc.FanRPM},
			{ID: "f2", Name: "Fan 2", Speed: bmc.ReadingOf(40), Units: bmc.FanPercent}},
		Power: bmc.PowerDraw{ConsumedWatts: bmc.ReadingOf(250)},
		PSUs: []bmc.PSU{{ID: "PSU1", Name: "PS1", InputWatts: bmc.ReadingOf(130), OutputWatts: bmc.ReadingOf(120),
			RatedInputWatts: bmc.ReadingOf(900)}},
		Voltages: []bmc.Voltage{{ID: "v1", Name: "System Board 3.3V", Volts: bmc.ReadingOf(3.31)},
			{ID: "v2", Name: "CPU1 VCORE PG", Volts: bmc.ReadingOf(1), Health: bmc.HealthOK}},
	})
}

func sampleKeys(ss []store.SensorSample) map[string]store.SensorSample {
	out := map[string]store.SensorSample{}
	for _, s := range ss {
		out[s.Key] = s
	}
	return out
}

// TestHistorySamples: every family with its kind and unit, valid readings only, one per
// key, PSU input and output (never the rated figure), analog rails without power-good
// signals, and the switches.
func TestHistorySamples(t *testing.T) {
	all := HistorySamples(historySnapshot(), AllSampling())
	got := sampleKeys(all)
	want := map[string]struct {
		kind  store.SensorKind
		unit  store.SensorUnit
		name  string
		value float64
	}{
		"temp:t1":        {store.SensorTemp, store.UnitCelsius, "Inlet", 22},
		"fan:Fan 1":      {store.SensorFan, store.UnitRPM, "Fan 1", 7000},
		"fan:f2":         {store.SensorFan, store.UnitPercent, "Fan 2", 40},
		"power:consumed": {store.SensorPower, store.UnitWatts, "Power draw", 250},
		"psu_in:PSU1":    {store.SensorPSUIn, store.UnitWatts, "PS1 input", 130},
		"psu_out:PSU1":   {store.SensorPSUOut, store.UnitWatts, "PS1 output", 120},
		"volt:v1":        {store.SensorVolt, store.UnitVolts, "System Board 3.3V", 3.31},
	}
	if len(all) != len(want) {
		t.Fatalf("samples = %+v", all)
	}
	for k, w := range want {
		s, ok := got[k]
		if !ok || s.Kind != w.kind || s.Unit != w.unit || s.Name != w.name || s.Value != w.value {
			t.Errorf("%s = %+v, want %+v", k, s, w)
		}
	}
	none := sampleKeys(HistorySamples(historySnapshot(), Sampling{}))
	for _, k := range []string{"psu_in:PSU1", "psu_out:PSU1", "volt:v1"} {
		if _, ok := none[k]; ok {
			t.Errorf("%s sampled with its switch off", k)
		}
	}
	if len(none) != 4 {
		t.Errorf("switches off = %d samples, want 4", len(none))
	}
}

// TestStoreSamplesClockJump: a poll older than the stored samples logs one warning and
// records the jump once per occurrence; history failures never stop polling.
func TestStoreSamplesClockJump(t *testing.T) {
	var logs bytes.Buffer
	samples := &fakeSamples{}
	cfg := Config{Samples: samples, Sampling: func() Sampling { return Sampling{} },
		Logger: slog.New(slog.NewTextHandler(&logs, nil))}.withDefaults()
	p := newPoller(cfg, Target{ID: "x", Driver: &countingDriver{}})
	ctx := context.Background()
	snap := historySnapshot()
	p.storeSamples(ctx, snap)
	samples.set(true, nil)
	p.storeSamples(ctx, snap)
	p.storeSamples(ctx, snap)
	if n, j := samples.counts(); n != 3 || j != 1 {
		t.Fatalf("polls %d, jumps %d; want 3 and one jump", n, j)
	}
	samples.set(false, nil)
	p.storeSamples(ctx, snap)
	samples.set(true, nil)
	p.storeSamples(ctx, snap)
	if _, j := samples.counts(); j != 2 {
		t.Fatalf("a second occurrence: %d jumps", j)
	}
	if strings.Count(logs.String(), "clock moved back") != 2 {
		t.Errorf("log: %s", logs.String())
	}
	samples.set(false, errors.New("disk full"))
	p.storeSamples(ctx, snap)
	if !strings.Contains(logs.String(), "store samples failed") {
		t.Errorf("insert failure not logged: %s", logs.String())
	}
	samples.mu.Lock()
	defer samples.mu.Unlock()
	if len(samples.polls[0].Samples) != 4 || !samples.polls[0].TS.Equal(t0) || samples.polls[0].ServerID != "x" {
		t.Errorf("poll = %+v (Sampling switches the PSUs and rails off)", samples.polls[0])
	}
}

// hostileSnapshot invents a fresh name for every sensor on every poll.
func hostileSnapshot(poll int) bmc.Snapshot {
	var ts []bmc.Temperature
	for i := 0; i < 300; i++ {
		ts = append(ts, bmc.Temperature{ID: fmt.Sprintf("p%d-t%d", poll, i), Name: "x", Celsius: bmc.ReadingOf(30)})
	}
	return bmc.NewSnapshot(bmc.SnapshotParams{TakenAt: t0.Add(time.Duration(poll) * time.Minute), Temperatures: ts})
}

// TestHostileBMCCannotGrowTheHistory (review HIGH-1): a BMC that invents sensor names
// every poll is cut to 128 temperatures a poll by the sampler and to
// store.MaxKeysPerServer keys by the store; refusals are counted and logged once.
func TestHostileBMCCannotGrowTheHistory(t *testing.T) {
	if n := len(HistorySamples(hostileSnapshot(0), AllSampling())); n != maxSampleTemps {
		t.Fatalf("%d samples from one poll", n)
	}
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var logs bytes.Buffer
	cfg := Config{Samples: db.History(), Logger: slog.New(slog.NewTextHandler(&logs, nil))}.withDefaults()
	p := newPoller(cfg, Target{ID: "x", Driver: &countingDriver{}})
	var refused int64
	for poll := 0; poll < 8; poll++ {
		refused += p.storeSamples(context.Background(), hostileSnapshot(poll))
	}
	keys, _ := db.History().Keys(context.Background(), "x")
	if len(keys) != store.MaxKeysPerServer || refused != 8*maxSampleTemps-store.MaxKeysPerServer {
		t.Fatalf("%d keys, %d refused", len(keys), refused)
	}
	if strings.Count(logs.String(), "more sensors than the history keeps") != 1 {
		t.Errorf("log: %s", logs.String())
	}
}

func TestHistorySamplesCapsEveryFamily(t *testing.T) {
	var fans []bmc.Fan
	var psus []bmc.PSU
	var volts []bmc.Voltage
	for i := 0; i < 100; i++ {
		id := fmt.Sprint(i)
		fans = append(fans, bmc.Fan{ID: id, Speed: bmc.ReadingOf(1)})
		psus = append(psus, bmc.PSU{ID: id, InputWatts: bmc.ReadingOf(1), OutputWatts: bmc.ReadingOf(1)})
		volts = append(volts, bmc.Voltage{ID: id, Name: "Rail " + id, Volts: bmc.ReadingOf(1)})
	}
	got := HistorySamples(bmc.NewSnapshot(bmc.SnapshotParams{Fans: fans, PSUs: psus, Voltages: volts}), AllSampling())
	if want := maxSampleFans + 2*maxSamplePSUs + maxSampleVolts; len(got) != want {
		t.Fatalf("%d samples, want %d", len(got), want)
	}
}

// TestUnitFlipsAreLoggedOnceAndCostNothing: a fan flipping between RPM and percent is
// logged once per poller and drops nothing (the store swaps two keys).
func TestUnitFlipsAreLoggedOnceAndCostNothing(t *testing.T) {
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var logs bytes.Buffer
	cfg := Config{Samples: db.History(), Logger: slog.New(slog.NewTextHandler(&logs, nil))}.withDefaults()
	p := newPoller(cfg, Target{ID: "x", Driver: &countingDriver{}})
	var counted int64
	for i := 0; i < store.MaxArchivesPerKey+3; i++ {
		units := bmc.FanRPM
		if i%2 == 1 {
			units = bmc.FanPercent
		}
		snap := bmc.NewSnapshot(bmc.SnapshotParams{TakenAt: t0.Add(time.Duration(i) * time.Minute),
			Fans: []bmc.Fan{{ID: "f1", Speed: bmc.ReadingOf(float64(i)), Units: units}}})
		counted += p.storeSamples(context.Background(), snap)
	}
	if counted != 0 || strings.Count(logs.String(), "changed its unit or kind") != 1 {
		t.Fatalf("two-unit flips: counted %d, log %s", counted, logs.String())
	}
}

// TestDroppedArchivesAreLoggedAndCounted: archives the store dropped are logged every
// time and counted with the refusals.
func TestDroppedArchivesAreLoggedAndCounted(t *testing.T) {
	var logs bytes.Buffer
	samples := &fakeSamples{dropped: 2}
	cfg := Config{Samples: samples, Logger: slog.New(slog.NewTextHandler(&logs, nil))}.withDefaults()
	p := newPoller(cfg, Target{ID: "x", Driver: &countingDriver{}})
	if n := p.storeSamples(context.Background(), historySnapshot()); n != 2 ||
		!strings.Contains(logs.String(), "oldest archived history was deleted") {
		t.Fatalf("counted %d, log %s", n, logs.String())
	}
}

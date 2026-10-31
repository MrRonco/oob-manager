package main

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/bmcreset"
	"oob-manager/internal/config"
	"oob-manager/internal/fleet"
	"oob-manager/internal/secrets"
	"oob-manager/internal/store"
)

func TestBMCResetTargets(t *testing.T) {
	mock := redfishmock.New(t, redfishmock.FixtureDir(t, "idrac9-r240"), redfishmock.WithManagerReset(0))
	creds, err := secrets.ParseCredentials([]byte("r2-op: {username: " + redfishmock.OperatorUser +
		", password: " + redfishmock.OperatorPassword + "}\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := consoleTestConfig(mock.PinSHA256())
	cfg.Servers[0].Credentials.Operator = "absent"
	cfg.Servers[1].Power.SelfHost = true
	var logs bytes.Buffer
	ts := bmcResetTargets(cfg, creds, func(config.Server) string { return mock.URL() }, slog.New(slog.NewTextHandler(&logs, nil)))
	if len(ts) != 3 || ts[0].Open != nil || ts[2].Open != nil || ts[1].Open == nil || !ts[1].SelfHost {
		t.Fatalf("targets %+v", ts)
	}
	if ts[0].Deadline != 5*time.Minute || ts[1].Deadline != 3*time.Minute {
		t.Fatalf("deadlines %v %v", ts[0].Deadline, ts[1].Deadline)
	}
	if !strings.Contains(logs.String(), "bmc restart unavailable") {
		t.Fatalf("log %s", logs.String())
	}
	r, err := ts[1].Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = r.Close(context.Background())
	if st := mock.ManagerResetStats(); st.Resets != 1 {
		t.Fatalf("mock %+v", st)
	}
	if def := bmcResetTargets(config.Config{Servers: cfg.Servers[2:]}, creds, nil, slog.Default()); len(def) != 1 {
		t.Fatalf("default endpoint targets %+v", def)
	}
	bad := cfg
	bad.Servers = []config.Server{cfg.Servers[1]}
	bad.Servers[0].TLSPinSHA256 = strings.Repeat("0", 64)
	if _, err := bmcResetTargets(bad, creds, func(config.Server) string { return mock.URL() }, slog.Default())[0].Open(context.Background()); err == nil {
		t.Fatal("a wrong pin must fail the login")
	}
}

func TestBMCResetAdaptersWithoutTheService(t *testing.T) {
	if apiBMCReset(nil) != nil || metricsBMCReset(nil) != nil {
		t.Fatal("nil service: nil hooks")
	}
	afterBMCBack(consoleDeps{}, slog.Default(), time.Millisecond)(context.Background(), "r1") // nothing wired: a no-op
}

func TestBMCResetAdapters(t *testing.T) {
	svc, err := bmcreset.New(bmcreset.Config{Targets: []bmcreset.Target{{ServerID: "r1"}}, Audit: nopAudit{},
		Store: openTestStore(t).BMCResets(), Fleet: nopRestartFleet{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := apiBMCReset(svc)("r1"); ok {
		t.Fatal("no reset yet")
	}
	if st := metricsBMCReset(svc)("r1"); !st.LastVerified.IsZero() || len(st.Counts) != 0 {
		t.Fatalf("metrics %+v", st)
	}
}

func openTestStore(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// nopRestartFleet accepts and cancels windows without a poller.
type nopRestartFleet struct{}

func (nopRestartFleet) ExpectRestart(string, fleet.RestartWindow, func(fleet.RestartEnd)) error {
	return nil
}

func (nopRestartFleet) CancelRestart(string) bool { return false }

// TestPowerInterlockSeesARequestInFlight (review S-M1): power waits while a BMC reset
// is being requested, before its window opens.
func TestPowerInterlockSeesARequestInFlight(t *testing.T) {
	fl, err := fleet.New(fleet.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var ptr atomic.Pointer[bmcreset.Service]
	hook := powerInterlock(fl, &ptr)
	if hook("r1") {
		t.Fatal("busy without a service")
	}
	in, release := make(chan struct{}), make(chan struct{})
	open := func(context.Context) (bmcreset.Resetter, error) { // the login is slow
		close(in)
		<-release
		return nil, bmc.ErrUnreachable
	}
	svc, err := bmcreset.New(bmcreset.Config{Targets: []bmcreset.Target{{ServerID: "r1", Open: open}}, Audit: nopAudit{},
		Store: openTestStore(t).BMCResets(), Fleet: nopRestartFleet{}})
	if err != nil {
		t.Fatal(err)
	}
	ptr.Store(svc)
	done := make(chan error, 1)
	go func() { done <- svc.Request(context.Background(), "r1", bmcreset.Actor{Username: "u"}) }()
	<-in
	if !hook("r1") || hook("r2") {
		t.Fatal("the interlock does not see the request in flight")
	}
	close(release)
	<-done
	if hook("r1") {
		t.Fatal("still busy after the refused request")
	}
}

// capturingFleet keeps each window's callback so a test can end it.
type capturingFleet struct {
	mu   sync.Mutex
	done map[string]func(fleet.RestartEnd)
}

func (f *capturingFleet) ExpectRestart(id string, _ fleet.RestartWindow, done func(fleet.RestartEnd)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.done[id] = done
	return nil
}

func (f *capturingFleet) CancelRestart(string) bool { return false }

func (f *capturingFleet) end(id string, e fleet.RestartEnd) {
	f.mu.Lock()
	done := f.done[id]
	f.mu.Unlock()
	done(e)
}

// TestOnlyAConfirmedRestartIsTheLastReset (review N3): the metric's last restart and the
// API's record ignore a return that did not confirm the restart.
func TestOnlyAConfirmedRestartIsTheLastReset(t *testing.T) {
	for _, tc := range []struct {
		name      string
		lastReset time.Time
		counts    bool
	}{
		{"LastResetTime unchanged", time.Now().Add(-24 * time.Hour), false},
		{"LastResetTime moved", time.Now().Add(time.Hour), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cf := &capturingFleet{done: map[string]func(fleet.RestartEnd){}}
			open := func(context.Context) (bmcreset.Resetter, error) { return okResetter{}, nil }
			svc, err := bmcreset.New(bmcreset.Config{Targets: []bmcreset.Target{{ServerID: "r1", Open: open}},
				Audit: nopAudit{}, Store: openTestStore(t).BMCResets(), Fleet: cf})
			if err != nil {
				t.Fatal(err)
			}
			defer svc.Shutdown()
			if err := svc.Request(context.Background(), "r1", bmcreset.Actor{Username: "u"}); err != nil {
				t.Fatal(err)
			}
			caps := bmc.NewCapabilities(bmc.CapabilityParams{Flags: bmc.CapabilityFlags{BMCLastReset: tc.lastReset,
				ProbedAt: time.Now().Add(time.Hour)}})
			cf.end("r1", fleet.RestartEnd{Outcome: fleet.RestartBack, At: time.Now(),
				State: fleet.ServerState{HasCapabilities: true, Capabilities: caps}})
			deadline := time.Now().Add(5 * time.Second)
			for svc.State("r1").Last.Result != store.BMCResetVerified && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if got := !metricsBMCReset(svc)("r1").LastVerified.IsZero(); got != tc.counts {
				t.Fatalf("metric last restart set %v, want %v", got, tc.counts)
			}
		})
	}
}

type okResetter struct{}

func (okResetter) Reset(context.Context) error { return nil }
func (okResetter) Close(context.Context) error { return nil }

// fakeReapplier fails the first failures attempts.
type fakeReapplier struct {
	mu        sync.Mutex
	failures  int
	attempts  int
	requested []string
}

func (f *fakeReapplier) ReapplyAfterBMCReset(context.Context, string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	if f.attempts <= f.failures {
		return false, bmc.ErrUnreachable
	}
	return true, nil
}

func (f *fakeReapplier) RequestReapply(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requested = append(f.requested, id)
}

// TestReapplyFanFloorRetries (review code MEDIUM): success on attempt N stops; all
// failing hands over to the reconciler without a wasted pause after the last attempt.
func TestReapplyFanFloorRetries(t *testing.T) {
	for _, tc := range []struct {
		failures, attempts int
		handedOver         bool
	}{{0, 1, false}, {2, 3, false}, {3, 4, false}, {9, fanReapplyAttempts, true}} {
		f := &fakeReapplier{failures: tc.failures}
		start := time.Now()
		reapplyFanFloor(context.Background(), f, "r2", 20*time.Millisecond, slog.Default())
		if f.attempts != tc.attempts || (len(f.requested) == 1) != tc.handedOver {
			t.Fatalf("failures %d: attempts %d handed over %v", tc.failures, f.attempts, f.requested)
		}
		if tc.handedOver {
			// Pauses 20+40+80 ms between four attempts; a pause after the last would add 160.
			if d := time.Since(start); d >= 300*time.Millisecond {
				t.Fatalf("took %v: a pause after the final attempt?", d)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &fakeReapplier{failures: 9}
	reapplyFanFloor(ctx, f, "r2", time.Hour, slog.Default())
	if f.attempts != 1 || len(f.requested) != 1 {
		t.Fatalf("cancelled: attempts %d requested %v", f.attempts, f.requested)
	}
}

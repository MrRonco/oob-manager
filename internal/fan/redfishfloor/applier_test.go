package redfishfloor

import (
	"context"
	"errors"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/dellredfish"
	"oob-manager/internal/bmc/redfish"
	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/fan"
	"oob-manager/internal/store"
)

type fakeFloor struct {
	floor   dellredfish.FanFloor
	readErr error
	setErr  error
	sets    []int
}

func (f *fakeFloor) Read(context.Context) (dellredfish.FanFloor, error) { return f.floor, f.readErr }
func (f *fakeFloor) Set(_ context.Context, v int) error {
	f.sets = append(f.sets, v)
	return f.setErr
}

func lease(pct int, orig int, has bool) store.FanLease {
	at := time.Unix(1_800_000_000, 0)
	return store.FanLease{LeaseID: "x", ServerID: "node-b", Pct: pct, IssuedAt: at, ExpiresAt: at.Add(time.Hour),
		State: store.LeaseApplied, OriginalValue: orig, HasOriginal: has}
}

func TestPrepareClampsToTheBMCRange(t *testing.T) {
	cases := []struct {
		floor        dellredfish.FanFloor
		pct, safeMin int
		want         fan.Plan
	}{
		{dellredfish.FanFloor{Current: 255, Low: 35, High: 100}, 50, 41, fan.Plan{Pct: 50, Original: 255, HasOriginal: true}},
		{dellredfish.FanFloor{Current: 255, Low: 45, High: 100}, 41, 41, fan.Plan{Pct: 45, Original: 255, HasOriginal: true}},
		{dellredfish.FanFloor{Current: 255, Low: 35, High: 80}, 95, 41, fan.Plan{Pct: 80, Original: 255, HasOriginal: true}},
		// Boost only: a floor already set higher by someone else is never lowered.
		{dellredfish.FanFloor{Current: 70, Low: 35, High: 100}, 50, 41, fan.Plan{Pct: 70, Original: 70, HasOriginal: true}},
	}
	for _, c := range cases {
		a := New(&fakeFloor{floor: c.floor})
		got, err := a.Prepare(context.Background(), c.pct, c.safeMin)
		if err != nil || got.Pct != c.want.Pct || got.Original != c.want.Original || !got.HasOriginal {
			t.Errorf("Prepare(%d) on %+v = %+v %v", c.pct, c.floor, got, err)
		}
	}
	low := New(&fakeFloor{floor: dellredfish.FanFloor{Current: 255, Low: 35, High: 40}})
	if _, err := low.Prepare(context.Background(), 50, 41); err == nil {
		t.Error("a BMC maximum below the safe minimum must refuse the lease")
	}
	broken := New(&fakeFloor{readErr: bmc.ErrTimeout})
	if _, err := broken.Prepare(context.Background(), 50, 41); !errors.Is(err, bmc.ErrTimeout) {
		t.Errorf("read error: %v", err)
	}
}

func TestApplyAndRelease(t *testing.T) {
	f := &fakeFloor{}
	a := New(f)
	if imm, err := a.Apply(context.Background(), lease(60, 255, true)); err != nil || !imm {
		t.Fatalf("apply = %v %v", imm, err)
	}
	for _, c := range []struct {
		orig int
		has  bool
		want int
	}{{255, true, 255}, {70, true, 70}, {0, false, 255}, {254, true, 255}, {-3, true, 255}, {0, true, 255}} {
		f.sets = nil
		if err := a.Release(context.Background(), lease(60, c.orig, c.has)); err != nil || len(f.sets) != 1 || f.sets[0] != c.want {
			t.Errorf("release with original %d/%v: sets %v err %v", c.orig, c.has, f.sets, err)
		}
	}
	f.setErr = bmc.ErrAuth
	if _, err := a.Apply(context.Background(), lease(60, 255, true)); !errors.Is(err, bmc.ErrAuth) {
		t.Errorf("apply error: %v", err)
	}
	o := a.Observe(lease(60, 255, true), true)
	if !o.Applied || o.Owner != fan.OwnerLease || o.AppliedPct != 60 {
		t.Errorf("observe = %+v", o)
	}
	if o := a.Observe(store.FanLease{}, false); o.Owner != fan.OwnerBMC || o.Applied {
		t.Errorf("observe without lease = %+v", o)
	}
}

// End to end against the mock iDRAC9: the PATCH goes to the one attribute, the original
// value is restored.
func TestAgainstMockBMC(t *testing.T) {
	s := redfishmock.New(t, redfishmock.FixtureDir(t, "idrac9-r240"), redfishmock.WithFanFloor())
	cfg := redfish.Config{Endpoint: s.URL(), Username: redfishmock.OperatorUser, Password: redfishmock.OperatorPassword,
		PinSHA256: s.PinSHA256(), Timeout: 2 * time.Second}
	a := New(dellredfish.NewFanFloorClient(cfg))
	ctx := context.Background()
	plan, err := a.Prepare(ctx, 50, 41)
	if err != nil || plan.Pct != 50 || plan.Original != redfishmock.FanFloorAuto {
		t.Fatalf("plan = %+v %v", plan, err)
	}
	l := lease(plan.Pct, plan.Original, plan.HasOriginal)
	if _, err := a.Apply(ctx, l); err != nil {
		t.Fatal(err)
	}
	if err := a.Release(ctx, l); err != nil {
		t.Fatal(err)
	}
	st := s.FanFloorStats()
	if len(st.Patches) != 2 || st.Patches[0] != 50 || st.Patches[1] != redfishmock.FanFloorAuto || s.OtherWrites() != 0 || s.LiveSessions() != 0 {
		t.Fatalf("stats %+v other %d live %d", st, s.OtherWrites(), s.LiveSessions())
	}
}

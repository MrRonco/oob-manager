package bmc

import (
	"testing"
	"time"
)

// TestSnapshotWithPowerState (audit R2-08): a verified power transition overlays the
// power state of a published snapshot without touching the rest, and never modifies
// the original (snapshots are values).
func TestSnapshotWithPowerState(t *testing.T) {
	taken := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	orig := NewSnapshot(SnapshotParams{TakenAt: taken, PowerState: PowerOn, Health: HealthWarning,
		Temperatures: []Temperature{{ID: "t1", Celsius: ReadingOf(40)}}, Problems: []string{"power: timeout"}})
	if !orig.PowerAsOf().Equal(taken) {
		t.Fatalf("PowerAsOf defaults to TakenAt, got %v", orig.PowerAsOf())
	}
	at := taken.Add(90 * time.Second)
	next := orig.WithPowerState(PowerOff, at)
	if next.PowerState() != PowerOff || !next.PowerAsOf().Equal(at) || !next.TakenAt().Equal(taken) {
		t.Fatalf("overlay: state %s as of %v taken %v", next.PowerState(), next.PowerAsOf(), next.TakenAt())
	}
	if next.Health() != HealthWarning || len(next.Temperatures()) != 1 || len(next.Problems()) != 1 {
		t.Fatal("the overlay dropped other fields")
	}
	if orig.PowerState() != PowerOn || !orig.PowerAsOf().Equal(taken) {
		t.Fatal("the original snapshot was modified")
	}
}

package fleet

import "time"

// Clock is the time source the pollers schedule with. Tests inject a fake one; the
// per-cycle BMC timeout still uses a real context deadline (CycleTimeout).
type Clock interface {
	Now() time.Time
	// After returns a channel that receives once d has elapsed.
	After(d time.Duration) <-chan time.Time
}

// RealClock is the wall clock.
type RealClock struct{}

// Now returns time.Now().
func (RealClock) Now() time.Time { return time.Now() }

// After is time.After (timers are garbage-collected once unreferenced since Go 1.23).
func (RealClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

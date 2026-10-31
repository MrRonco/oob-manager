package fan

import (
	"context"
	"time"

	"oob-manager/internal/store"
)

// Owner is who is in charge of the fans, as the enforcing side reports it.
type Owner string

// Owners shown in the UI (PRD FR-14).
const (
	OwnerUnknown Owner = ""
	OwnerCurve   Owner = "curve" // host fan script, normal curve
	OwnerBMC     Owner = "bmc"   // the BMC's own automatic control
	OwnerLease   Owner = "lease" // a lease's floor is in effect
	OwnerGuard   Owner = "guard" // a thermal guard overrode everything (BMC automatic)
)

// Plan is what an applier will do for a request: the floor it will apply (after any
// clamp of its own) and the value to restore when the lease ends.
type Plan struct {
	Pct         int
	Original    int
	HasOriginal bool
}

// Observation is what the enforcing side last reported. It never causes BMC traffic.
type Observation struct {
	// Applied: the enforcing side confirmed this lease (hostlease ack for its ID).
	Applied    bool
	Owner      Owner
	AppliedPct int
	HasPct     bool
	ReportedAt time.Time
	// Warning is a short, user-safe sentence (stale report, guard, rejected file).
	Warning string
}

// Applier is one fan mode. Implementations must be safe for concurrent use; the
// service serialises calls per server.
type Applier interface {
	// Prepare checks the target before anything is persisted.
	Prepare(ctx context.Context, pct, safeMin int) (Plan, error)
	// Apply makes l effective. immediate reports that it is in effect now (no ack to
	// wait for). Apply must be idempotent: it is repeated at startup.
	Apply(ctx context.Context, l store.FanLease) (immediate bool, err error)
	// Release ends l's effect (removes the lease file, restores the original value).
	// It must be idempotent.
	Release(ctx context.Context, l store.FanLease) error
	// Observe reports the enforcing side's view; has is false when no lease is active.
	Observe(l store.FanLease, has bool) Observation
}

// Sweeper is optionally implemented by appliers that can leave state behind without a
// lease row (a lease file after a crash). Sweep removes it when no lease is active.
type Sweeper interface {
	Sweep(ctx context.Context) error
}

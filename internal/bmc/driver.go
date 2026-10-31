package bmc

import (
	"context"
	"time"
)

// Driver is the read-only contract every BMC driver implements (P1).
//
// Write operations (power, fan, consoles) are optional interfaces discovered by type
// assertion in later phases, never by vendor string checks. Implementations must be
// safe for concurrent use and must apply a timeout to every BMC request.
type Driver interface {
	// Probe discovers what this BMC offers. Absent endpoints turn capabilities off;
	// only transport, TLS-pin and auth failures are errors.
	Probe(ctx context.Context) (Capabilities, error)
	// Snapshot reads sensors, PSUs, power draw, health rollup and power state.
	Snapshot(ctx context.Context) (Snapshot, error)
	// EventLog reads SEL entries created after since (zero = all available).
	EventLog(ctx context.Context, since time.Time) (EventLog, error)
	// Inventory reads model, firmware and licence information.
	Inventory(ctx context.Context) (Inventory, error)
}

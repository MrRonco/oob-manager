// Package fleetview adapts the poller's read side (fleet.Reader) to the browser UI's
// data contract (ui.Fleet). It is pure mapping: it never calls a BMC. Event logs come
// from the SEL and Lifecycle logs the pollers cache in fleet.ServerState, so a page view
// can never trigger BMC traffic and server IDs only ever select configured servers.
package fleetview

import (
	"context"
	"fmt"
	"slices"

	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
	"oob-manager/internal/web/ui"
)

// Adapter implements ui.Fleet over a fleet.Reader. It holds no mutable state.
type Adapter struct {
	r         fleet.Reader
	lifecycle func(id string) bool
}

var _ ui.Fleet = Adapter{}

// New returns the adapter. lifecycle reports whether a server has a Dell Lifecycle
// Controller log (decided from config at startup); nil means no server has one.
func New(r fleet.Reader, lifecycle func(id string) bool) Adapter {
	if lifecycle == nil {
		lifecycle = func(string) bool { return false }
	}
	return Adapter{r: r, lifecycle: lifecycle}
}

// Servers returns every configured server in config order.
func (a Adapter) Servers() []ui.ServerView {
	states := a.r.Servers()
	out := make([]ui.ServerView, 0, len(states))
	for _, s := range states {
		out = append(out, view(s))
	}
	return out
}

// Server returns one server by config ID.
func (a Adapter) Server(id string) (ui.ServerView, bool) {
	s, ok := a.r.Server(id)
	if !ok {
		return ui.ServerView{}, false
	}
	return view(s), true
}

// Events returns the cached log of server id. A log that has not been read yet is an
// empty, incomplete log; a failed read returns an error of the recorded class only.
func (a Adapter) Events(ctx context.Context, id string, kind ui.LogKind) (bmc.EventLog, error) {
	if err := ctx.Err(); err != nil {
		return bmc.EventLog{}, err
	}
	s, ok := a.r.Server(id)
	if !ok {
		return bmc.EventLog{}, ui.ErrLogUnavailable
	}
	switch kind {
	case ui.LogSEL:
		return selLog(s)
	case ui.LogLifecycle:
		if !a.lifecycle(id) {
			return bmc.EventLog{}, ui.ErrLogUnavailable
		}
		return cached(s.Lifecycle, s.HasLifecycle, s.LifecycleError)
	default:
		return bmc.EventLog{}, ui.ErrLogUnavailable
	}
}

func selLog(s fleet.ServerState) (bmc.EventLog, error) {
	noSEL := s.HasCapabilities && !s.Capabilities.Flags().SEL
	if !s.HasSEL && (noSEL || s.SELError == bmc.ClassUnsupported) {
		return bmc.EventLog{}, ui.ErrLogUnavailable
	}
	return cached(s.SEL, s.HasSEL, s.SELError)
}

// cached prefers a successfully read log, even when a later refresh failed (the poller
// keeps the previous log), then the failure class, then "not read yet".
func cached(log bmc.EventLog, has bool, class bmc.ErrorClass) (bmc.EventLog, error) {
	switch {
	case has:
		return log, nil
	case class != bmc.ClassNone:
		return bmc.EventLog{}, classError(class)
	default:
		return bmc.NewEventLog("", nil, false), nil
	}
}

func view(s fleet.ServerState) ui.ServerView {
	return ui.ServerView{
		ID: s.ID, Name: s.Name, Tags: slices.Clone(s.Tags),
		Snapshot: s.Snapshot, HasSnapshot: s.HasSnapshot, Previous: s.Previous, HasPrevious: s.HasPrevious, LastSuccess: s.LastSuccess, ErrorClass: s.LastError,
		Inventory: s.Inventory, HasInventory: s.HasInventory,
		Capabilities: s.Capabilities, HasCapabilities: s.HasCapabilities,
		LastPollDuration: s.LastPollDuration, StaleAfter: s.StaleAfter,
		SELAsOf: s.SELAsOf, SELOverdue: s.SELOverdue, LifecycleAsOf: s.LifecycleAsOf, LifecycleOverdue: s.LifecycleOverdue,
		InventoryAsOf: s.InventoryAsOf, InventoryOverdue: s.InventoryOverdue, PinMismatch: s.PinMismatch,
		PowerSince: s.PowerSince, PowerCause: ui.PowerCause(s.PowerCause),
		Restarting: s.Restarting, Restart: ui.RestartWindow(s.Restart),
	}
}

// classError turns a recorded class back into an error that bmc.Classify maps to the
// same class. It carries no BMC text.
func classError(c bmc.ErrorClass) error {
	sentinels := map[bmc.ErrorClass]error{
		bmc.ClassTimeout:     bmc.ErrTimeout,
		bmc.ClassTLS:         bmc.ErrPinMismatch,
		bmc.ClassAuth:        bmc.ErrAuth,
		bmc.ClassBMC:         bmc.ErrBMC,
		bmc.ClassNotFound:    bmc.ErrNotFound,
		bmc.ClassUnsupported: bmc.ErrUnsupported,
		bmc.ClassUnreachable: bmc.ErrUnreachable,
		bmc.ClassProtocol:    bmc.ErrDecode,
		bmc.ClassConfig:      bmc.ErrInvalidConfig,
	}
	if err, ok := sentinels[c]; ok {
		return fmt.Errorf("fleetview: last log read failed: %w", err)
	}
	return fmt.Errorf("fleetview: last log read failed (%s)", c)
}

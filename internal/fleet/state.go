package fleet

import (
	"slices"
	"time"

	"oob-manager/internal/bmc"
)

// Reader is the read side of the fleet that the UI and the JSON API consume. All
// methods are cheap (atomic loads) and return values that are safe to share.
type Reader interface {
	// Servers returns every configured server in config order.
	Servers() []ServerState
	// Server returns one server by its config ID.
	Server(id string) (ServerState, bool)
	// Polled reports whether at least one server has produced a snapshot (/readyz).
	Polled() bool
}

// ServerState is an immutable view of one server, as of its last poll. Values are
// copied out of the fleet on every read; the bmc types inside are immutable.
type ServerState struct {
	ID   string
	Name string
	Tags []string
	// HistoryRefused counts samples of new sensors the history refused since the start
	// (the server reached store.MaxKeysPerServer), plus archived series it deleted (a
	// sensor past store.MaxArchivesPerKey unit or kind changes); oob_history_keys_refused_total.
	HistoryRefused int64

	// Snapshot is the latest successful sensor read (HasSnapshot=false until the first).
	Snapshot    bmc.Snapshot
	HasSnapshot bool
	// Previous is the successful snapshot before Snapshot (HasPrevious=false until the
	// second success). The UI compares readings with it for the value-change cue (plan 04
	// §11 item 5); a failed poll moves neither.
	Previous    bmc.Snapshot
	HasPrevious bool
	// SEL and Lifecycle are refreshed every Config.EventsEvery (the slow tier). Their
	// *Error fields hold the class of the last failed refresh (the previous log is kept);
	// *AsOf is when the kept value was read and *Overdue (computed on read) is true when
	// it is older than the tier period plus two poll intervals.
	SEL              bmc.EventLog
	HasSEL           bool
	SELError         bmc.ErrorClass
	Lifecycle        bmc.EventLog
	HasLifecycle     bool
	LifecycleError   bmc.ErrorClass
	SELAsOf          time.Time
	SELOverdue       bool
	LifecycleAsOf    time.Time
	LifecycleOverdue bool
	// Inventory and Capabilities are refreshed every Config.InventoryEvery (and at start).
	Inventory        bmc.Inventory
	HasInventory     bool
	InventoryError   bmc.ErrorClass
	Capabilities     bmc.Capabilities
	HasCapabilities  bool
	InventoryAsOf    time.Time
	InventoryOverdue bool
	// Posture is the last BMC security posture read (docs/tech_doc.md §31), refreshed
	// every PostureEvery, at start and on RequestPosture. PostureEnabled: the server has a
	// posture tier at all. PostureRequested: a re-run is waiting for the next cycle;
	// PostureRunning: the tier is reading now. PostureError is the class of the last
	// failed run (the previous posture is kept).
	Posture          bmc.Posture
	HasPosture       bool
	PostureError     bmc.ErrorClass
	PostureAsOf      time.Time
	PostureOverdue   bool
	PostureEnabled   bool
	PostureRequested bool
	PostureRunning   bool
	PostureEvery     time.Duration
	// Firmware tier (docs/tech_doc.md §38): FirmwareEnabled when the driver has a firmware
	// scanner and a sink is wired; FirmwareAsOf is the last good scan (zero: none since
	// start; the stored scan survives restarts in the sink), FirmwareNext when the tier is
	// next due, FirmwareError the class of the last failed scan.
	FirmwareEnabled   bool
	FirmwareAsOf      time.Time
	FirmwareNext      time.Time
	FirmwareError     bmc.ErrorClass
	FirmwareRequested bool
	FirmwareRunning   bool
	FirmwareEvery     time.Duration

	LastAttempt time.Time // last snapshot attempt (zero: never polled)
	LastSuccess time.Time // last successful snapshot
	// LastError is the class of the most recent failed snapshot; empty after a success.
	LastError bmc.ErrorClass
	// FailingSince is when the current failure streak began ("unreachable since …").
	FailingSince        time.Time
	ConsecutiveFailures int
	Breaker             BreakerState
	BreakerOpenUntil    time.Time
	// LastPollDuration is how long the last fast-tier read (the snapshot) took.
	LastPollDuration time.Duration
	// Interval is this server's poll interval (Config.Interval raised to its cycle
	// timeout); StaleAfter is Config.StaleAfter or 3 × Interval.
	Interval   time.Duration
	StaleAfter time.Duration

	// Stale is computed when the state is read: no snapshot yet, or the last success is
	// older than StaleAfter.
	Stale bool
	// PowerSince is when the current host power state was first observed by this
	// process (zero: unknown, the first poll already found the host in that state). It
	// moves only when the state changes between polls, or when a verified power action
	// (ObservePower) changes it.
	PowerSince time.Time
	// PowerCause is the verified power action that explains the current power state
	// (zero: none; a poll that sees another state clears it).
	PowerCause PowerCause
	// PinMismatch: the BMC presented a certificate that does not match the pinned SPKI.
	// Polling is then Paused (no retries) until a new fingerprint is confirmed and
	// applied (settings_design.md §8 decision 2), or the app restarts with a new pin.
	PinMismatch bool
	Paused      bool
	// Restarting: an expected BMC restart window is open (computed on read: the deadline
	// has not passed); Restart is that window (tech_doc §37).
	Restarting bool
	Restart    RestartWindow
}

// PowerCause names a verified power action: its slug (power.Action), the user and when
// the end state was observed.
type PowerCause struct {
	Action, By string
	At         time.Time
}

// PowerObservation is a verified power transition reported by the power service
// (ObservePower): the end state, when it was read, and the action and user behind it.
type PowerObservation struct {
	State      bmc.PowerState
	At         time.Time
	Action, By string
}

// Reachable reports whether the last snapshot attempt succeeded.
func (s ServerState) Reachable() bool { return s.HasSnapshot && s.ConsecutiveFailures == 0 }

// clone returns a copy that shares nothing mutable with s.
func (s ServerState) clone() ServerState {
	s.Tags = slices.Clone(s.Tags)
	return s
}

package power

import (
	"errors"
	"fmt"
	"time"

	"oob-manager/internal/bmc"
)

// Errors returned by Request. The UI maps each to a status and a sentence; BMC error
// text is never shown (only its class).
var (
	ErrNotConfigured = errors.New("power: server not configured")
	ErrNoOperator    = errors.New("power: needs an operator BMC account")
	ErrUnsupported   = errors.New("power: action not offered by this BMC")
	ErrState         = errors.New("power: action does not apply in the current power state")
	ErrAudit         = errors.New("power: audit record failed; nothing was sent")
	ErrCoolingDown   = errors.New("power: cooling down")
	ErrBMC           = errors.New("power: the BMC did not carry out the request")
	// ErrBMCRestarting: the server's BMC is restarting (tech_doc §37); its operator login
	// and the verification reads would both fail.
	ErrBMCRestarting = errors.New("power: the BMC is restarting")
)

// CooldownError says how long to wait before the next action on the server.
type CooldownError struct{ Left time.Duration }

func (e *CooldownError) Error() string { return fmt.Sprintf("power: cooling down for %v", e.Left) }

// Unwrap lets errors.Is(err, ErrCoolingDown) match.
func (e *CooldownError) Unwrap() error { return ErrCoolingDown }

// Phase is where an operation stands.
type Phase string

// Phases. Sending means the app is logging in and posting the reset; Pending means
// the BMC accepted it and the app is watching the power state; the other three are final.
const (
	PhaseSending     Phase = "sending"
	PhasePending     Phase = "pending"
	PhaseDone        Phase = "done"        // the expected power state was observed
	PhaseUnconfirmed Phase = "unconfirmed" // a restart was accepted but never seen leaving On
	PhaseFailed      Phase = "failed"      // refused, or the expected state never came
)

// Operation is the latest power operation on one server. It is a value; the service
// replaces it, never modifies it.
type Operation struct {
	Action      Action
	By          string
	RequestedAt time.Time
	FinishedAt  time.Time // zero while sending or pending
	Phase       Phase
	State       bmc.PowerState // last power state the app read
	// Class is the error class of a failure ("" otherwise): bmc.ErrorClass values or
	// not_confirmed, superseded, stopped.
	Class string
}

// Final reports whether the operation has finished.
func (o Operation) Final() bool { return o.Phase != PhaseSending && o.Phase != PhasePending }

// Applies reports whether a makes sense in state s: power on only when the host is not
// on, everything else only when it is not off. An unknown state allows every action.
func (a Action) Applies(s bmc.PowerState) bool {
	switch s {
	case bmc.PowerOn, bmc.PowerPoweringOn:
		return a != On
	case bmc.PowerOff, bmc.PowerPoweringOff:
		return a == On
	default:
		return true
	}
}

// reached reports whether the verification is complete. seenDown records that a
// restart was observed leaving On.
func reached(a Action, s bmc.PowerState, seenDown bool) bool {
	switch {
	case a == On || a.Restarts() && seenDown:
		return s == bmc.PowerOn
	case a.Restarts():
		return false
	default:
		return s == bmc.PowerOff
	}
}

package ui

import (
	"strings"

	"oob-manager/internal/authz"
	"oob-manager/internal/power"
)

// opDetail is a power action's sub-line in the Power menu.
func opDetail(a power.Action) string {
	switch a {
	case power.On:
		return "Starts the server."
	case power.GracefulShutdown:
		return "Asks the operating system to shut down."
	case power.GracefulRestart:
		return "Asks the operating system to restart."
	case power.ForceOff:
		return "Cuts power at once. Unsaved data is lost."
	case power.PowerCycle:
		return "Off, then on again. Unsaved data is lost."
	default:
		return "Resets the server at once."
	}
}

// powerActions is the safe or forced group: each action links to its confirm page, or
// is disabled with the first reason that applies (direction B C-10).
func (s *server) powerActions(v ServerView, p authz.Principal, forced bool) []opAction {
	var out []opAction
	for _, a := range power.Actions() {
		if a.Forced() != forced {
			continue
		}
		op := opAction{Label: a.Label(), Detail: opDetail(a), Forced: forced}
		if b := s.powerBlocked(v, p, a, true); b.why != "" {
			op.Why = b.why
		} else {
			op.Href = powerPath(v.ID, a)
		}
		out = append(out, op)
	}
	return out
}

// powerStatus is the latest power operation, as the server Overview's Now panel shows it.
type powerStatus struct {
	Badge healthView
	Text  string
}

// powerStatusFor describes the latest operation on server id (nil: none since start).
func (s *server) powerStatusFor(id string, tf timeFmt) *powerStatus {
	op, ok := s.d.Power.Last(id)
	if !ok {
		return nil
	}
	who := " (requested by " + op.By + " at " + tf.full(op.RequestedAt) + ")"
	when := tf.full(op.FinishedAt)
	want := expectedLabel(op.Action)
	switch op.Phase {
	case power.PhaseSending:
		return &powerStatus{healthView{"Sending", "info"}, op.Action.Label() + ": logging in to the BMC and sending the request" + who + "."}
	case power.PhasePending:
		return &powerStatus{healthView{"In progress", "info"}, op.Action.Label() + " accepted by the BMC" + who +
			". Waiting for the server to report " + want + "; reload this page to see the result."}
	case power.PhaseDone:
		return &powerStatus{healthView{"Done", "ok"}, op.Action.Label() + " done: the server reported " +
			powerLabel(op.State) + " at " + when + who + "."}
	case power.PhaseUnconfirmed:
		return &powerStatus{healthView{"Unconfirmed", "warn"}, op.Action.Label() + " accepted" + who +
			", but the server reported On the whole time. A restart can be too quick to see; check the server."}
	default:
		return &powerStatus{healthView{"Failed", "crit"}, op.Action.Label() + " failed: " + failText(op.Class, want) + who + "."}
	}
}

func expectedLabel(a power.Action) string {
	if a == power.On || a.Restarts() {
		return "On"
	}
	return "Off"
}

func failText(class, want string) string {
	switch class {
	case "not_confirmed":
		return "the server did not report " + want + " in time"
	case "superseded":
		return "a newer power action replaced it before the result was known"
	case "stopped":
		return "oob-manager stopped before the result was known"
	case "unsupported":
		return "the BMC does not offer it"
	case "state":
		return "it did not apply to the power state at the time"
	case "auth":
		return "the BMC refused the operator login or the request"
	case "timeout":
		return "the BMC did not answer in time"
	case "unreachable":
		return "the BMC could not be reached"
	default:
		return "the BMC returned an error (" + class + ")"
	}
}

// describePower names a power confirm path for the step-up page ("Force off · Edge
// router"); only configured server names and the enum's labels are interpolated.
func (s *server) describePower(next string) string {
	id, slug, ok := strings.Cut(strings.TrimPrefix(next, "/servers/"), "/power/")
	a, known := power.ParseAction(slug)
	if !ok || !known || !serverIDPattern.MatchString(id) {
		return ""
	}
	if v, found := s.d.Fleet.Server(id); found {
		return a.Label() + " · " + v.Name
	}
	return ""
}

// Package power is host power control (P2): a closed set of actions, intersected with
// what each BMC advertises, sent with the server's operator login, limited by a
// per-server cooldown, verified by polling the host power state, and audited at every
// step (requested, denied, succeeded, failed).
//
// Nothing user-supplied reaches a BMC: the server ID is looked up in config and the
// action is one of the six constants below; the Redfish body is built from the constant.
package power

import "oob-manager/internal/authz"

// Action is a closed enum of power actions. The value is the URL slug.
type Action string

// Actions. Safe actions ask the operating system (or only power on); forced actions
// cut or reset power at once.
const (
	On               Action = "on"
	GracefulShutdown Action = "graceful-shutdown"
	GracefulRestart  Action = "graceful-restart"
	ForceOff         Action = "force-off"
	PowerCycle       Action = "power-cycle"
	ForceRestart     Action = "force-restart"
)

// Actions returns every action, safe ones first (a fresh slice each call).
func Actions() []Action {
	return []Action{On, GracefulShutdown, GracefulRestart, ForceOff, PowerCycle, ForceRestart}
}

// ParseAction validates a slug exactly.
func ParseAction(s string) (Action, bool) {
	for _, a := range Actions() {
		if string(a) == s {
			return a, true
		}
	}
	return "", false
}

// spec is everything known about one action.
type spec struct {
	resetType string
	authz     authz.Action
	forced    bool
	label     string
	effect    string
}

func specOf(a Action) spec {
	switch a {
	case On:
		return spec{"On", authz.PowerOn, false, "Power on", "Starts the server."}
	case GracefulShutdown:
		return spec{"GracefulShutdown", authz.PowerGracefulStop, false, "Graceful shutdown",
			"Asks the operating system to shut down. It can take minutes, and an operating system can ignore it."}
	case GracefulRestart:
		return spec{"GracefulRestart", authz.PowerGracefulRestart, false, "Graceful restart",
			"Asks the operating system to restart."}
	case ForceOff:
		return spec{"ForceOff", authz.PowerForceOff, true, "Force off",
			"Cuts power at once. Unsaved data is lost and file systems are not shut down cleanly."}
	case PowerCycle:
		return spec{"PowerCycle", authz.PowerCycle, true, "Power cycle",
			"Turns power off, then on again. Unsaved data is lost."}
	case ForceRestart:
		return spec{"ForceRestart", authz.PowerForceRestart, true, "Force restart",
			"Resets the server at once, without shutting the operating system down. Unsaved data is lost."}
	default:
		return spec{}
	}
}

// ResetType is the Redfish ComputerSystem.Reset value ("" for an unknown action).
func (a Action) ResetType() string { return specOf(a).resetType }

// Authz is the permission the action needs.
func (a Action) Authz() authz.Action { return specOf(a).authz }

// Forced reports whether the action cuts or resets power without the OS.
func (a Action) Forced() bool { return specOf(a).forced }

// Label is the button text ("Force off").
func (a Action) Label() string { return specOf(a).label }

// Effect says what the action does, in one or two sentences.
func (a Action) Effect() string { return specOf(a).effect }

// TakesDown reports whether the action stops or restarts the host (everything but On).
func (a Action) TakesDown() bool { return a != On }

// Restarts reports whether the host is expected to come back on by itself.
func (a Action) Restarts() bool {
	return a == GracefulRestart || a == PowerCycle || a == ForceRestart
}

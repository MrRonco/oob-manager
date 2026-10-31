package ui

import (
	"cmp"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/power"
)

// Power-state semantics (audit R2-01, tech_doc §32). A host that is not running is its
// own non-OK state: the sensor rollup is meaningless while it is off, and "all servers
// healthy" must never be said about a fleet with a server down.
//
//   - Off or powering off: the state badge reads "Powered off" (class off, power-off icon); the
//     attention item is a warning, or critical for a critical-tagged server. When this
//     app ran a graceful shutdown for a user and the host went off right after, the item
//     reads "Powered off (by <user>, <time>): graceful shutdown." and is informational.
//     A forced power-off is named too but stays a warning: nobody plans to leave it off.
//   - Powering on: badge "Powering on" (class off), an informational item.
//   - Unknown power state on fresh data: badge "Power unknown", counted as unknown.
//   - Powering on and unknown replace only an OK sensor badge: a warning keeps its badge
//     (as in the metrics and notifications) and the power item follows the sensor items.
//   - A critical sensor rollup outranks the power state; maintenance and stale data
//     outrank everything (summary.go).

// powerContext is the verified power action that explains a server's current power
// state (zero: none does).
type powerContext struct {
	Action power.Action
	By     string
	At     time.Time
}

// planned reports whether the power-down was asked for through this app as an orderly
// shutdown.
func (p powerContext) planned() bool { return p.Action == power.GracefulShutdown }

// forced reports whether a user cut the power through this app.
func (p powerContext) forced() bool {
	return p.Action.Forced() && p.Action.TakesDown() && !p.Action.Restarts()
}

// powerContextFor finds the action that explains v's power state. The fleet carries it
// once a verified transition was published (PowerCause, audit R2-08); otherwise the
// power service's latest operation counts when it finished in that state and the state
// was first seen within one stale threshold of its end (a later transition, or one
// before the app started, is not explained by it).
func (s *server) powerContextFor(v ServerView) powerContext {
	if a, ok := power.ParseAction(v.PowerCause.Action); ok && v.PowerCause.By != "" {
		return powerContext{Action: a, By: v.PowerCause.By, At: v.PowerCause.At}
	}
	if s.d.Power == nil || !v.HasSnapshot || v.PowerSince.IsZero() {
		return powerContext{}
	}
	op, ok := s.d.Power.Last(v.ID)
	if !ok || op.Phase != power.PhaseDone || op.State != v.Snapshot.PowerState() {
		return powerContext{}
	}
	slack := cmp.Or(v.StaleAfter, s.d.StaleAfter)
	if d := v.PowerSince.Sub(op.FinishedAt); d < -slack || d > slack {
		return powerContext{}
	}
	return powerContext{Action: op.Action, By: op.By, At: op.FinishedAt}
}

// hostDown reports whether the host is off or on its way off.
func hostDown(p bmc.PowerState) bool { return p == bmc.PowerOff || p == bmc.PowerPoweringOff }

// hostBadge is the state badge of a server whose host is not running; ok is false when
// the host is on (the sensor badge applies).
func hostBadge(p bmc.PowerState, critical, planned bool) (healthView, bool) {
	switch {
	case hostDown(p) && critical && !planned:
		return healthView{Label: powerLabel2(p), Class: "crit"}, true
	case hostDown(p):
		return healthView{Label: powerLabel2(p), Class: "off"}, true
	case p == bmc.PowerPoweringOn:
		return healthView{Label: "Powering on", Class: "off"}, true
	case p == bmc.PowerUnknown:
		return healthView{Label: "Power unknown", Class: "unknown"}, true
	default:
		return healthView{}, false
	}
}

// powerLabel2 is the badge word for a host that is down.
func powerLabel2(p bmc.PowerState) string {
	if p == bmc.PowerPoweringOff {
		return "Powering off"
	}
	return "Powered off"
}

// powerAttention is the attention item of a host that is not running (nil when it is
// on): what, since when, by whom, at the severity the state deserves.
func powerAttention(name, href string, p bmc.PowerState, critical bool, since time.Time, ctx powerContext, tf timeFmt) *attentionItem {
	item := &attentionItem{Server: name, Href: href, Jump: "power", JumpHref: href + "#s-h"}
	switch {
	case hostDown(p) && ctx.planned():
		item.Text = "Powered off (by " + ctx.By + ", " + tf.full(ctx.At) + "): graceful shutdown."
		item.Health = healthView{Label: "Planned", Class: "info"}
	case hostDown(p):
		item.Text = powerLabel2(p)
		if !since.IsZero() {
			item.Text += " since " + tf.full(since)
		}
		if ctx.forced() {
			item.Text += " (forced off by " + ctx.By + ")"
		}
		item.Text += "."
		item.Health = healthOf(bmc.HealthWarning)
		if critical {
			item.Health = healthOf(bmc.HealthCritical)
		}
	case p == bmc.PowerPoweringOn:
		item.Text, item.Health = "Powering on.", healthView{Label: "Booting", Class: "info"}
	case p == bmc.PowerUnknown:
		item.Text, item.Health = "Power state not reported by the BMC.", healthOf(bmc.HealthUnknown)
	default:
		return nil
	}
	return item
}

// powerNote is the short form shown next to the power state (Status panel, server
// header): the verified action behind it, else since when the host has been down.
func powerNote(p bmc.PowerState, since time.Time, ctx powerContext, tf timeFmt) string {
	switch {
	case ctx.Action != "":
		return "verified " + tf.full(ctx.At) + " (" + lowerFirst(ctx.Action.Label()) + " by " + ctx.By + ")"
	case hostDown(p) && !since.IsZero():
		return "since " + tf.full(since)
	default:
		return ""
	}
}

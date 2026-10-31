package notify

import (
	"encoding/json"
	"fmt"

	"oob-manager/internal/audit"
)

// bmcReset maps the BMC restart trail (tech_doc §37) to the bmc class: requested
// (warning), back (the recovery of the request, so the pair reads problem/resolved),
// failed (warning) and did not come back by the deadline (critical: the one that should
// wake someone). Refusals before anything was sent raise nothing.
func (t *Tap) bmcReset(r record) (Event, bool) {
	e := t.serverEvent(ClassBMC, r)
	e.Key = "bmc/" + r.server
	switch {
	case r.action == "bmc.reset" && afterStarted(r.params) &&
		(r.result == audit.ResultDenied || r.result == audit.ResultError):
		// Refused after the started row, before anything was sent: close the
		// "requested" alert so it does not dangle (review S-L4).
		e.Severity, e.Recovery = SeverityWarning, true
		e.Title = e.ServerName + ": BMC restart not sent"
		e.Message = fmt.Sprintf("The BMC restart of %s requested by %s was not sent (%s); nothing restarted.",
			e.ServerName, r.principal, orText(r.class, "unknown"))
	case r.action == "bmc.reset" && r.result == audit.ResultStarted:
		e.Severity = SeverityWarning
		e.Title = e.ServerName + ": BMC restart requested"
		e.Message = fmt.Sprintf("%s requested a restart of %s's BMC. Consoles close and monitoring pauses until it is back; the host keeps running.",
			r.principal, e.ServerName)
	case r.action == "bmc.reset" && r.result == audit.ResultError:
		e.Severity = SeverityWarning
		e.Title = e.ServerName + ": BMC restart failed"
		e.Message = fmt.Sprintf("The BMC of %s did not accept the restart requested by %s (%s).", e.ServerName, r.principal,
			orText(r.class, "unknown"))
	case r.action == "bmc.reset.verified" && r.result == audit.ResultOK && !restartConfirmed(r.params):
		// The BMC answers again, but nothing confirms that it restarted (review N3).
		e.Severity, e.Recovery = SeverityWarning, true
		e.Title = e.ServerName + ": BMC answers again, restart not confirmed"
		e.Message = fmt.Sprintf("The BMC of %s answers again%s, but it did not confirm the restart (no answer to "+
			"the request, or its last restart time did not move). Check the BMC.", e.ServerName, downtime(r.params))
	case r.action == "bmc.reset.verified" && r.result == audit.ResultOK:
		e.Severity, e.Recovery = SeverityWarning, true
		e.Title = e.ServerName + ": BMC back"
		e.Message = fmt.Sprintf("The BMC of %s answers again%s after its restart.", e.ServerName, downtime(r.params))
	case r.action == "bmc.reset.verified" && r.result == audit.ResultError:
		return t.bmcNotBack(e, r), true
	default:
		return Event{}, false
	}
	return e, true
}

func (t *Tap) bmcNotBack(e Event, r record) Event {
	e.Severity = SeverityWarning
	switch r.class {
	case "timeout":
		e.Severity = SeverityCritical
		e.Title = e.ServerName + ": BMC did not come back"
		e.Message = fmt.Sprintf("The BMC of %s did not answer by the deadline after its restart. Open the BMC web UI or check the server.",
			e.ServerName)
	case "config_changed":
		e.Title = e.ServerName + ": BMC restart no longer watched"
		e.Message = fmt.Sprintf("The connection settings of %s changed during its BMC restart; the restart is no longer watched.", e.ServerName)
	default:
		e.Title = e.ServerName + ": BMC restart not confirmed"
		e.Message = fmt.Sprintf("The BMC restart of %s could not be confirmed (%s).", e.ServerName, orText(r.class, "unknown"))
	}
	return e
}

// afterStarted reports a bmc.reset refusal that follows its started row.
func afterStarted(params string) bool {
	var p struct {
		AfterStarted bool `json:"after_started"`
	}
	return json.Unmarshal([]byte(params), &p) == nil && p.AfterStarted
}

// restartConfirmed reads restart_confirmed of a verified row (absent: confirmed, the
// rows written before the field existed).
func restartConfirmed(params string) bool {
	var p struct {
		Confirmed *bool `json:"restart_confirmed"`
	}
	return json.Unmarshal([]byte(params), &p) != nil || p.Confirmed == nil || *p.Confirmed
}

// downtime renders " after N s" from the verified row's downtime_s ("" when absent).
func downtime(params string) string {
	var p struct {
		Downtime *int64 `json:"downtime_s"`
	}
	if json.Unmarshal([]byte(params), &p) != nil || p.Downtime == nil {
		return ""
	}
	return fmt.Sprintf(" %d s", *p.Downtime)
}

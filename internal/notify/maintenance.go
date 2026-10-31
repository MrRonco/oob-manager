package notify

import (
	"strconv"
	"time"
)

// Suppressor is maintenance mode and event acknowledgement as notifications see them
// (implemented by *maint.Service, tech_doc §28). Both methods are lock-free reads.
type Suppressor interface {
	// InMaintenance reports whether serverID has an active maintenance window at now:
	// its Mutable classes (health, reachability, logs, PSU) are not sent.
	InMaintenance(serverID string, now time.Time) bool
	// Acked reports whether the log entry (server, log "sel" or "lifecycle", BMC entry
	// id, BMC timestamp) was acknowledged: it never raises a log notification.
	Acked(serverID, log, entryID string, created time.Time) bool
}

// MaintenanceChange describes a maintenance window that started or ended.
type MaintenanceChange struct {
	ServerID, ServerName string
	Started              bool      // false: ended
	Until                time.Time // zero: until ended (Started only)
	Reason               string    // operator text, one line
	By                   string    // who started or ended it ("system" when it expired)
	Expired              bool      // ended on its own
	// Reminder marks the daily reminder of a window that lasts until it is ended
	// (Started is ignored); Since is when that window began.
	Reminder bool
	Since    time.Time
}

const maintTime = "2006-01-02 15:04 MST"

// MaintenanceEvent is the single message sent when a server's maintenance window starts
// or ends. Its class is ClassMaintenance: it is never suppressed and goes to every target
// that subscribes to a class maintenance pauses. The reason is operator-entered text,
// not BMC text; control characters become spaces on the wire like every title.
func MaintenanceEvent(c MaintenanceChange, now time.Time) Event {
	e := Event{ID: newEventID(), Class: ClassMaintenance, Severity: SeverityWarning, ServerID: c.ServerID,
		ServerName: c.ServerName, Key: "maintenance/" + c.ServerID, At: now}
	reason := clip(oneLine(c.Reason), 200)
	if c.Reminder {
		return maintenanceReminder(e, c, reason, now)
	}
	if c.Started {
		until := "until it is ended (a reminder follows once a day)"
		if !c.Until.IsZero() {
			until = "until " + c.Until.UTC().Format(maintTime)
		}
		e.Title = c.ServerName + ": maintenance started"
		e.Message = c.ServerName + " is in maintenance " + until + " (" + c.By + ": " + reason + "). Health, " +
			"unreachable, log and power supply alerts for it are paused; power, console, sign-in and trust alerts are not."
		return e
	}
	e.Recovery = true // the pause is over (priority stays normal, see Event.quiet)
	e.Title = c.ServerName + ": maintenance ended"
	how := "was ended by " + c.By
	if c.Expired {
		how = "expired"
	}
	e.Message = "Maintenance of " + c.ServerName + " " + how + ". Alerts for it are sent again; problems still " +
		"present are reported after the usual delay."
	return e
}

// maintenanceReminder is the once-a-day "still in maintenance" message of an open-ended
// window: the pause has no end time, so it is easy to forget.
func maintenanceReminder(e Event, c MaintenanceChange, reason string, now time.Time) Event {
	days := int(now.Sub(c.Since) / (24 * time.Hour))
	unit := " days"
	if days == 1 {
		unit = " day"
	}
	e.Title = c.ServerName + ": still in maintenance"
	e.Message = c.ServerName + " has been in maintenance since " + c.Since.UTC().Format(maintTime) + " (" +
		strconv.Itoa(days) + unit + ") with no end time (" + c.By + ": " + reason + "). Health, unreachable, log " +
		"and power supply alerts for it are still paused. End the maintenance when the work is done."
	return e
}

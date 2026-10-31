package notify

import (
	"strconv"
	"strings"
	"time"
)

// maxListedUpdates bounds the updates named in one message (plan 08 §13), and
// maxUpdateBytes the list's size, so the "and N more" tail survives a target's message
// cap (Pushover's is 1024 bytes).
const (
	maxListedUpdates = 16
	maxUpdateBytes   = 700
)

// FirmwareUpdate is one newly available vendor release as a message names it: the
// server, the app's display name of the component and the two versions (catalog text,
// cleaned and capped at import).
type FirmwareUpdate struct {
	ServerName, Component, Running, Latest string
	Urgent                                 bool
}

// FirmwareUpdatesEvent is the single message of an import that found new updates. It is
// a warning when any is rated Urgent (the default subscription, warning and above, sees
// only those), else info; it never pages (Event.quiet).
func FirmwareUpdatesEvent(ups []FirmwareUpdate, now time.Time) Event {
	e := Event{ID: newEventID(), Class: ClassFirmware, Severity: SeverityInfo, Key: "firmware/updates",
		Count: len(ups), At: now}
	urgent := 0
	ordered := make([]FirmwareUpdate, 0, len(ups)) // urgent ones first
	for _, u := range ups {
		if u.Urgent {
			urgent++
			ordered = append(ordered, u)
		}
	}
	for _, u := range ups {
		if !u.Urgent {
			ordered = append(ordered, u)
		}
	}
	lines := make([]string, 0, min(len(ups), maxListedUpdates))
	size := 0
	for _, u := range ordered {
		l := u.ServerName + ": " + u.Component + " " + u.Running + " → " + u.Latest
		if u.Urgent {
			l += " (urgent)"
		}
		if len(lines) == maxListedUpdates || size+len(l) > maxUpdateBytes {
			break
		}
		lines, size = append(lines, l), size+len(l)+2
	}
	if extra := len(ups) - len(lines); extra > 0 {
		lines = append(lines, "and "+strconv.Itoa(extra)+" more")
	}
	if urgent > 0 {
		e.Severity = SeverityWarning
	}
	switch {
	case len(ups) == 1 && urgent == 1:
		e.Title = "Urgent firmware update available"
	case len(ups) == 1:
		e.Title = "Firmware update available"
	case urgent > 0:
		e.Title = strconv.Itoa(len(ups)) + " new firmware updates (" + strconv.Itoa(urgent) + " urgent)"
	default:
		e.Title = strconv.Itoa(len(ups)) + " new firmware updates"
	}
	e.Message = "The vendor catalog lists newer firmware. This app never installs it: update on the BMC itself. " +
		strings.Join(lines, "; ") + "."
	return e
}

// CatalogFailingEvent says the online update check failed three times in a row (sent once
// until a check succeeds); class is the last failure's class.
func CatalogFailingEvent(class string, failures int, now time.Time) Event {
	return Event{ID: newEventID(), Class: ClassFirmware, Severity: SeverityWarning, Key: "firmware/check", At: now,
		Title: "Firmware update check failing",
		Message: "The online firmware update check failed " + strconv.Itoa(failures) + " times in a row (last: " + class +
			"). The previous catalog stays in use; see Firmware for details."}
}

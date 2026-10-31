package notify

import (
	"fmt"
	"strconv"
	"time"
)

// maxFirmwareDetail bounds the change lines one firmware message lists.
const maxFirmwareDetail = 16

// FirmwareChangeLine is one version change as the Detail lists it. Component and the
// versions are BMC text: they appear in Detail only.
type FirmwareChangeLine struct {
	Component, Field, Before, After string
}

// FirmwareChange is what one firmware scan of a server found changed (tech_doc §38):
// Components counts the components with a change worth a message (a running version,
// a staged image, a component that appeared or disappeared).
type FirmwareChange struct {
	ServerID, ServerName string
	Components           int
	Lines                []FirmwareChangeLine
}

// FirmwareEvent is the single message for one scan's firmware changes (design decision,
// like the security class). A warning, so the default "warning and above"
// subscription receives it; the class is sent at normal priority and never pages. One
// message per scan, whatever the number of components, so a fleet-wide update cannot
// flood a target's bucket that critical classes share.
func FirmwareEvent(c FirmwareChange, now time.Time) Event {
	e := Event{ID: newEventID(), Class: ClassSecurity, Severity: SeverityWarning, ServerID: c.ServerID,
		ServerName: c.ServerName, Key: "security/firmware/" + c.ServerID, Count: c.Components, At: now}
	what := "1 component"
	if c.Components != 1 {
		what = strconv.Itoa(c.Components) + " components"
	}
	e.Title = c.ServerName + ": firmware changed on " + what
	e.Message = fmt.Sprintf("The firmware of %s of %s changed since the last scan (a version, a staged image, or a component "+
		"that appeared or disappeared). If nobody updated it, check the BMC and the host; the Inventory tab lists the changes.",
		what, c.ServerName)
	for i, l := range c.Lines {
		if i == maxFirmwareDetail {
			e.Detail = append(e.Detail, "and "+strconv.Itoa(len(c.Lines)-i)+" more")
			break
		}
		e.Detail = append(e.Detail, fmt.Sprintf("%s: %s %s → %s", l.Component, l.Field, orText(l.Before, "none"), orText(l.After, "none")))
	}
	return e
}

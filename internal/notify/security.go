package notify

import (
	"strconv"
	"strings"
	"time"
)

// maxListedFindings bounds the findings named in one security message.
const maxListedFindings = 5

// SecurityFinding is one new BMC security check finding as a message names it: the
// check's title and result label from the app's own catalog, never BMC text.
type SecurityFinding struct {
	Title  string
	Result string // "Warning" or "Fail"
	Fail   bool
}

// SecurityChange is what one run of a server's security checks found new: findings that
// newly warn or fail, or got worse, since the last notification (tech_doc §31).
type SecurityChange struct {
	ServerID, ServerName string
	New                  []SecurityFinding
	Open                 int // findings that are open (warn or fail, not accepted) after the run
}

// SecurityEvent is the single message for a server's new security findings. Every new
// finding is a warning or a failure, so the message is a warning (targets subscribe to
// "warning and above" by default and must see it); like a weekly digest it is sent at
// normal priority (Event.quiet) and is never paused by maintenance mode.
func SecurityEvent(c SecurityChange, now time.Time) Event {
	e := Event{ID: newEventID(), Class: ClassSecurity, Severity: SeverityWarning, ServerID: c.ServerID,
		ServerName: c.ServerName, Key: "security/" + c.ServerID, Count: len(c.New), At: now}
	names := make([]string, 0, maxListedFindings)
	for i, f := range c.New {
		if i < maxListedFindings {
			names = append(names, f.Title+" ("+f.Result+")")
		}
	}
	list := strings.Join(names, "; ")
	if extra := len(c.New) - len(names); extra > 0 {
		list += " and " + strconv.Itoa(extra) + " more"
	}
	if len(c.New) == 1 {
		e.Title = c.ServerName + ": new BMC security finding"
	} else {
		e.Title = c.ServerName + ": " + strconv.Itoa(len(c.New)) + " new BMC security findings"
	}
	open := strconv.Itoa(c.Open) + " findings are open"
	if c.Open == 1 {
		open = "1 finding is open"
	}
	e.Message = "New: " + list + ". " + open + " on this BMC; see its Security tab."
	return e
}

// CertReminder is a certificate of a server's BMC that expires soon.
type CertReminder struct {
	ServerID, ServerName string
	Port                 string // "HTTPS" or "VNC"
	Days                 int    // whole days left (0: less than a day)
	NotAfter             time.Time
}

// CertExpiryEvent reminds that a BMC certificate expires soon (14, 7 and 1 days before).
// Warning from a week before, info before that; normal priority like every security
// message.
func CertExpiryEvent(r CertReminder, now time.Time) Event {
	e := Event{ID: newEventID(), Class: ClassSecurity, Severity: SeverityInfo, ServerID: r.ServerID,
		ServerName: r.ServerName, Key: "security/cert/" + r.ServerID + "/" + r.Port, At: now}
	if r.Days <= 7 {
		e.Severity = SeverityWarning
	}
	when := "in " + strconv.Itoa(r.Days) + " days"
	switch r.Days {
	case 0:
		when = "within a day"
	case 1:
		when = "in 1 day"
	}
	e.Title = r.ServerName + ": " + r.Port + " certificate expires " + when
	e.Message = "The " + r.Port + " certificate of " + r.ServerName + "'s BMC expires on " +
		r.NotAfter.UTC().Format(maintTime) + ". Renew it; if the new one has a new key, confirm its fingerprint in Settings → Servers."
	return e
}

package bmcsec

import (
	"fmt"
	"time"
)

// maxClockDrift: a BMC clock further than this from the app's is a warning.
const maxClockDrift = 60 * time.Second

func timeEntries() []entry {
	return []entry{
		{check: Check{ID: "svc.ntp", Group: GroupServices, Title: "NTP time sync",
			Why:  "Without time sync the BMC clock drifts: event log times stop matching other logs, and certificate validity checks can go wrong.",
			Fix:  "Turn NTP on and point it at one or more reliable time servers.",
			Dell: "racadm set iDRAC.NTPConfigGroup.NTPEnable 1, and NTP1 to NTP3 for the servers.",
			Docs: "https://www.rfc-editor.org/rfc/rfc8633"},
			eval: ntp},
		{check: Check{ID: "svc.clock", Group: GroupServices, Title: "BMC clock",
			Why: "Event log entries carry the BMC's time. A clock that is minutes off misleads anyone matching BMC events with other logs, " +
				"and shifts certificate validity.",
			Fix: "Turn on NTP (see NTP time sync), or set the clock."},
			eval: clock},
		{check: Check{ID: "svc.syslog", Group: GroupServices, Title: "Remote syslog",
			Why:  "A BMC keeps only a small log of its own. A copy on a syslog server survives a full log, a reset, or an attacker clearing it.",
			Fix:  "Send the BMC's log to a syslog server.",
			Dell: "racadm set iDRAC.SysLog.SysLogEnable 1, and Server1 for the server.",
			Docs: "https://www.rfc-editor.org/rfc/rfc5424"},
			eval: syslog},
	}
}

func ntp(c evalCtx) outcome {
	pr := c.p.Redfish.Protocols
	switch {
	case !pr.NTP.Known:
		return missing("whether NTP is on", pr.Read, c.p.Redfish.Attributes)
	case !pr.NTP.Value:
		return out(Warn, "off", "NTP is off"+from(pr.NTP.Source)+".")
	case pr.NTPServers.Known && pr.NTPServers.Value == "":
		return out(Warn, "no-server", "NTP is on but no server is set"+from(pr.NTPServers.Source)+".")
	case pr.NTPServers.Known:
		return out(Pass, "", "NTP is on: "+pr.NTPServers.Value+from(pr.NTPServers.Source)+".")
	default:
		return out(Pass, "", "NTP is on"+from(pr.NTP.Source)+".")
	}
}

// clock compares the BMC's time with the app clock read just before and after it, so
// the request time does not count as drift.
func clock(c evalCtx) outcome {
	k := c.p.Redfish.Clock
	if !k.Read.OK() {
		return unread(k.Read, "the BMC clock")
	}
	var drift time.Duration
	dir := "ahead of"
	switch {
	case k.BMCTime.Before(k.Before):
		drift, dir = k.Before.Sub(k.BMCTime), "behind"
	case k.BMCTime.After(k.After):
		drift = k.BMCTime.Sub(k.After)
	}
	if drift > maxClockDrift {
		return out(Warn, dir, fmt.Sprintf("The BMC clock is %s %s oob-manager's clock.", roundDrift(drift), dir))
	}
	return out(Pass, "", fmt.Sprintf("Within %s of oob-manager's clock.", roundDrift(max(drift, time.Second))))
}

func roundDrift(d time.Duration) string {
	switch {
	case d >= 2*time.Hour:
		return plural(int(d/time.Hour), "hour", "hours")
	case d >= 2*time.Minute:
		return plural(int(d/time.Minute), "minute", "minutes")
	default:
		return plural(int(d/time.Second), "second", "seconds")
	}
}

func syslog(c evalCtx) outcome {
	pr := c.p.Redfish.Protocols
	switch {
	case !pr.Syslog.Known:
		return missing("remote syslog", pr.Read, c.p.Redfish.Attributes)
	case !pr.Syslog.Value:
		return out(Info, "", "Remote syslog is off"+from(pr.Syslog.Source)+": the BMC's log lives only on the BMC.")
	case pr.SyslogServers.Known && pr.SyslogServers.Value == 0:
		return out(Info, "", "Remote syslog is on but no server is set"+from(pr.SyslogServers.Source)+".")
	case pr.SyslogServers.Known:
		return out(Pass, "", "Remote syslog is on, to "+plural(pr.SyslogServers.Value, "server", "servers")+from(pr.SyslogServers.Source)+".")
	default:
		return out(Pass, "", "Remote syslog is on"+from(pr.Syslog.Source)+".")
	}
}

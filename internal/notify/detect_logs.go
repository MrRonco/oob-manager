package notify

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
)

// observeLogs reports new warning/critical entries of the SEL and the Lifecycle log.
// The first read of a log is the baseline: history is never sent.
func observeLogs(tr serverTrack, s fleet.ServerState, now time.Time,
	acked func(serverID, log, entryID string, created time.Time) bool) (serverTrack, []Event) {
	logs := map[string]bmc.EventLog{}
	if s.HasSEL {
		logs["sel"] = s.SEL
	}
	if s.HasLifecycle {
		logs["lifecycle"] = s.Lifecycle
	}
	marks := make(map[string]logMark, len(tr.logs))
	for k, v := range tr.logs {
		marks[k] = v
	}
	var out []Event
	for _, name := range []string{"sel", "lifecycle"} {
		log, ok := logs[name]
		if !ok {
			continue
		}
		prev, seen := marks[name]
		fresh, mark := newEntries(prev, seen, log.Entries())
		if acked != nil {
			fresh = slices.DeleteFunc(fresh, func(ev bmc.Event) bool { return acked(s.ID, name, ev.ID, ev.Created) })
		}
		marks[name] = mark
		if e, ok := logEvent(s, name, fresh, now); ok {
			out = append(out, e)
		}
	}
	tr.logs = marks
	return tr, out
}

// newEntries returns the warning/critical entries not seen before and the new mark.
// An entry is new if its ID is unseen or it is newer than anything seen (a cleared
// log restarts its IDs).
func newEntries(prev logMark, baselined bool, entries []bmc.Event) ([]bmc.Event, logMark) {
	mark := logMark{seen: make(map[string]bool, len(entries)), newest: prev.newest}
	var fresh []bmc.Event
	for _, ev := range entries {
		mark.seen[ev.ID] = true
		if ev.Created.After(mark.newest) {
			mark.newest = ev.Created
		}
		isNew := !prev.seen[ev.ID] || (!ev.Created.IsZero() && ev.Created.After(prev.newest))
		if baselined && isNew && (ev.Severity == bmc.SeverityWarning || ev.Severity == bmc.SeverityCritical) {
			fresh = append(fresh, ev)
		}
	}
	return fresh, mark
}

func logEvent(s fleet.ServerState, name string, fresh []bmc.Event, now time.Time) (Event, bool) {
	if len(fresh) == 0 {
		return Event{}, false
	}
	crit := 0
	for _, ev := range fresh {
		if ev.Severity == bmc.SeverityCritical {
			crit++
		}
	}
	label := map[string]string{"sel": "System Event Log", "lifecycle": "Lifecycle log"}[name]
	e := base(ClassSEL, s, "log/"+s.ID+"/"+name, now)
	e.Severity, e.Count = SeverityWarning, len(fresh)
	if crit > 0 {
		e.Severity = SeverityCritical
	}
	e.Title = fmt.Sprintf("%s: %d new %s entr%s", s.Name, len(fresh), strings.ToLower(e.Severity.String()), plural(len(fresh), "y", "ies"))
	e.Message = fmt.Sprintf("%d new entr%s in the %s of %s (%d critical, %d warning). Open the server's logs for details.",
		len(fresh), plural(len(fresh), "y", "ies"), label, s.Name, crit, len(fresh)-crit)
	for i, ev := range fresh {
		if i == maxDetail {
			break
		}
		e.Detail = append(e.Detail, clip(oneLine(string(ev.Severity)+": "+ev.Message), 300))
	}
	return e, true
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func newEventID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

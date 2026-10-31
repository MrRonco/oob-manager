package ui

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"time"

	"oob-manager/internal/bmc"
)

// repeatMarker matches the iDRAC "previous entry repeated" record (MessageId LOG007),
// which is folded into the entry it refers to as "×N" (UX-05).
var repeatMarker = regexp.MustCompile(`^The previous log entry was repeated (\d+) times?\.?$`)

// foldedEvent is a log entry with its repeat count (total occurrences; 0 = once).
type foldedEvent struct {
	Event  bmc.Event
	Repeat int
}

// foldRepeats folds repeat markers into the entry they refer to. es is newest first, so
// "the previous entry" is the next (older) one. A marker with nothing older left in the
// slice stays a row of its own.
func foldRepeats(es []bmc.Event) []foldedEvent {
	out := make([]foldedEvent, 0, len(es))
	pending := 0
	var marker *bmc.Event
	for i := range es {
		if n, ok := repeatCount(es[i]); ok {
			pending += n
			marker = &es[i]
			continue
		}
		f := foldedEvent{Event: es[i]}
		if pending > 0 {
			f.Repeat = pending + 1
		}
		out = append(out, f)
		pending, marker = 0, nil
	}
	if marker != nil {
		out = append(out, foldedEvent{Event: *marker})
	}
	return out
}

func repeatCount(e bmc.Event) (int, bool) {
	m := repeatMarker.FindStringSubmatch(e.Message)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n < 1 || n > 1_000_000 {
		return 0, false
	}
	return n, true
}

// logSeverity is the badge of a log entry: an informational entry is "Info" (neutral),
// never the green "OK" reserved for health (UX-05).
func logSeverity(s bmc.Severity) healthView {
	switch s {
	case bmc.SeverityOK:
		return healthView{Label: "Info", Class: "info"}
	case bmc.SeverityWarning:
		return healthOf(bmc.HealthWarning)
	case bmc.SeverityCritical:
		return healthOf(bmc.HealthCritical)
	default:
		return healthOf(bmc.HealthUnknown)
	}
}

// fleetEvent is one folded log entry with the server and log it came from.
type fleetEvent struct {
	ServerID, ServerName, Log string
	Kind                      LogKind
	Event                     bmc.Event
	Repeat                    int
}

// fleetEvents merges the cached logs of the given servers, folded and newest first by
// BMC timestamp (entries without a time last). notes name logs that could not be read.
func (s *server) fleetEvents(ctx context.Context, views []ServerView, kinds []LogKind) ([]fleetEvent, []string) {
	var all []fleetEvent
	var notes []string
	for _, sv := range views {
		for _, kind := range kinds {
			log, err := s.d.Fleet.Events(ctx, sv.ID, kind)
			if errors.Is(err, ErrLogUnavailable) {
				continue
			}
			if err != nil {
				notes = append(notes, sv.Name+": "+logLabel(kind)+" could not be read ("+errorText(bmc.Classify(err))+")")
				continue
			}
			for _, f := range foldRepeats(log.Entries()) {
				all = append(all, fleetEvent{ServerID: sv.ID, ServerName: sv.Name, Log: logLabel(kind), Kind: kind,
					Event: f.Event, Repeat: f.Repeat})
			}
		}
	}
	slices.SortStableFunc(all, func(a, b fleetEvent) int { return compareNewest(a.Event.Created, b.Event.Created) })
	return all, notes
}

// recentProblems returns warning and critical entries newer than since.
func recentProblems(all []fleetEvent, since time.Time) []fleetEvent {
	var out []fleetEvent
	for _, e := range all {
		if isProblem(e.Event.Severity) && e.Event.Created.After(since) {
			out = append(out, e)
		}
	}
	return out
}

// compareNewest orders newest first, entries without a timestamp last.
func compareNewest(a, b time.Time) int {
	switch {
	case a.IsZero() && b.IsZero():
		return 0
	case a.IsZero():
		return 1
	case b.IsZero():
		return -1
	default:
		return b.Compare(a)
	}
}

func logLabel(k LogKind) string {
	if k == LogLifecycle {
		return "Lifecycle"
	}
	return "SEL"
}

// eventRow is one log entry as rendered.
type eventRow struct {
	Record, Created, Message, MessageID, Type, Code, Sensor string
	Short, Rel, ISO                                         string // "10:31", "13 min ago"
	Severity                                                healthView
	Repeat                                                  int
	ServerID, ServerName, Log                               string
	Day                                                     string // day separator label, set on the first row of a day
	// Ref names a warning or critical entry for Acknowledge ("" for other entries); Ack
	// is set when it is acknowledged.
	Ref string
	Ack *ackView
	// Form is the page's acknowledge form settings (nil: no buttons); Idx makes field ids unique.
	Form *ackForm
	Idx  int
}

func (s *server) eventRow(e bmc.Event, repeat int, tf timeFmt) eventRow {
	now := s.d.Now()
	r := eventRow{Record: e.ID, Created: tf.full(e.Created), Message: e.Message, MessageID: e.MessageID,
		Type: e.EntryType, Code: e.EntryCode, Sensor: e.SensorType, Severity: logSeverity(e.Severity), Repeat: repeat,
		Short: tf.short(e.Created, now)}
	if !e.Created.IsZero() {
		r.Rel, r.ISO = fmtRel(now, e.Created), e.Created.UTC().Format(time.RFC3339)
	}
	return r
}

// fleetRows renders fleet events, marking the first row of each local day.
func (s *server) fleetRows(es []fleetEvent, days bool, tf timeFmt) []eventRow {
	out := make([]eventRow, 0, len(es))
	last := ""
	for _, e := range es {
		r := s.withAck(s.eventRow(e.Event, e.Repeat, tf), e.ServerID, e.Kind, e.Event, tf)
		r.ServerName, r.Log = e.ServerName, e.Log
		if day := dayLabel(e.Event.Created, s.d.Now(), tf.loc); days && day != last {
			r.Day, last = day, day
		}
		out = append(out, r)
	}
	return out
}

package redfish

import (
	"context"
	"fmt"
	"time"

	"oob-manager/internal/bmc"
)

const (
	maxLogPages   = 8
	maxLogEntries = 2000
)

// EventLog reads the SEL from the location found by Probe.
func (d *Driver) EventLog(ctx context.Context, since time.Time) (bmc.EventLog, error) {
	disc, err := d.discovered(ctx)
	if err != nil {
		return bmc.EventLog{}, err
	}
	if disc.res.SELEntries == "" {
		return bmc.EventLog{}, fmt.Errorf("event log: %w: no SEL entries collection", bmc.ErrUnsupported)
	}
	return d.ReadLog(ctx, disc.res.SELEntries, since)
}

type logCursor struct {
	entries  []bmc.Event
	read     int // raw members seen, before the since filter
	total    int // Members@odata.count of the first page, -1 if absent
	complete bool
}

// ReadLog reads a LogEntry collection (following nextLink, bounded) and keeps entries
// created after since. OEM drivers use it for Dell Lifecycle logs. A failure on the
// first page is an error; a failure on a later page marks the log incomplete.
func (d *Driver) ReadLog(ctx context.Context, uri string, since time.Time) (bmc.EventLog, error) {
	cur := logCursor{total: -1, complete: true}
	next := uri
	for page := 0; next != ""; page++ {
		if page >= maxLogPages || len(cur.entries) >= maxLogEntries {
			cur.complete = false
			break
		}
		var doc logPageDoc
		if err := d.GetJSON(ctx, next, &doc); err != nil {
			if page == 0 || ctx.Err() != nil {
				return bmc.EventLog{}, err
			}
			cur.complete = false
			break
		}
		if page == 0 && doc.Count != nil {
			cur.total = *doc.Count
		}
		// No early exit on "nothing newer here": BMCs differ in sort order (some are
		// oldest-first), so every page up to the cap is read.
		cur.add(doc.Members, since)
		next = doc.NextLink
		if next != "" && checkURI(next) != nil {
			cur.complete = false
			break
		}
	}
	if cur.total > cur.read {
		cur.complete = false
	}
	return bmc.NewEventLog(uri, cur.entries, cur.complete), nil
}

// add appends the entries created after since (all entries when since is zero).
func (c *logCursor) add(members []logEntryDoc, since time.Time) {
	for _, m := range members {
		c.read++
		e := toEvent(m)
		if !since.IsZero() && (e.Created.IsZero() || !e.Created.After(since)) {
			continue
		}
		if len(c.entries) < maxLogEntries {
			c.entries = append(c.entries, e)
		}
	}
}

func toEvent(m logEntryDoc) bmc.Event {
	created, err := time.Parse(time.RFC3339, clean(string(m.Created)))
	if err != nil {
		created = time.Time{}
	}
	return bmc.Event{
		ID:         clean(string(m.ID)),
		Created:    created,
		Severity:   bmc.ParseSeverity(string(m.Severity)),
		Message:    clean(string(m.Message)),
		MessageID:  clean(string(m.MessageID)),
		EntryType:  clean(string(m.EntryType)),
		EntryCode:  clean(string(m.EntryCode)),
		SensorType: clean(string(m.SensorType)),
	}
}

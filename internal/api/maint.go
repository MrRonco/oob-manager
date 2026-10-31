package api

import (
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/maint"
)

// MaintenanceReader is the read side of maintenance mode and acknowledgements
// (*maint.Service, tech_doc §28). Nil in Deps: the fields are null / empty.
type MaintenanceReader interface {
	Window(serverID string) (maint.Window, bool)
	Acks(serverID string) []maint.Ack
	AckOf(r maint.EventRef) (maint.Ack, bool)
}

// maintenanceJSON is a server's maintenance window (null when it has none). ends_at is
// null for a window that lasts until it is ended; active is false while it is scheduled.
type maintenanceJSON struct {
	Active   bool       `json:"active"`
	StartsAt time.Time  `json:"starts_at"`
	EndsAt   *time.Time `json:"ends_at"`
	Reason   string     `json:"reason"`
	By       string     `json:"by"`
}

// ackJSON is an acknowledged log entry. created is the entry's BMC timestamp (null when
// the BMC sent none); the entry is identified by server, log, entry_id and created.
type ackJSON struct {
	Log     string     `json:"log"`
	EntryID string     `json:"entry_id"`
	Created *time.Time `json:"created"`
	By      string     `json:"by"`
	At      time.Time  `json:"at"`
	Comment string     `json:"comment"`
}

// eventAckJSON is the acknowledgement attached to one event of /events.
type eventAckJSON struct {
	By      string    `json:"by"`
	At      time.Time `json:"at"`
	Comment string    `json:"comment"`
}

func (a *API) maintenanceOf(serverID string) *maintenanceJSON {
	if a.deps.Maintenance == nil {
		return nil
	}
	w, ok := a.deps.Maintenance.Window(serverID)
	if !ok {
		return nil
	}
	return &maintenanceJSON{Active: w.ActiveAt(a.deps.Now()), StartsAt: w.StartsAt, EndsAt: timePtr(w.EndsAt),
		Reason: w.Reason, By: w.By}
}

func (a *API) acksOf(serverID string) []ackJSON {
	out := []ackJSON{}
	if a.deps.Maintenance == nil {
		return out
	}
	for _, k := range a.deps.Maintenance.Acks(serverID) {
		out = append(out, ackJSON{Log: k.Ref.Log, EntryID: k.Ref.EntryID, Created: timePtr(k.Ref.Created), By: k.By,
			At: k.At, Comment: k.Comment})
	}
	return out
}

// eventAck returns the acknowledgement of one entry (nil when none).
func (a *API) eventAck(serverID, log string, e bmc.Event) *eventAckJSON {
	if a.deps.Maintenance == nil {
		return nil
	}
	k, ok := a.deps.Maintenance.AckOf(maint.EventRef{ServerID: serverID, Log: log, EntryID: e.ID, Created: e.Created})
	if !ok {
		return nil
	}
	return &eventAckJSON{By: k.By, At: k.At, Comment: k.Comment}
}

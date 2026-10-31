package api

import (
	"cmp"
	"encoding/base64"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
	"oob-manager/internal/web"
)

// Event paging limits (tech_doc §6: limit ≤ 200).
const (
	DefaultEventLimit = 50
	MaxEventLimit     = 200
)

// Log selectors for ?log=.
const (
	logSEL       = "sel"
	logLifecycle = "lifecycle"
)

type eventJSON struct {
	ID         string     `json:"id"`
	Created    *time.Time `json:"created"`
	Severity   string     `json:"severity"`
	Message    string     `json:"message"`
	MessageID  string     `json:"message_id,omitempty"`
	EntryType  string     `json:"entry_type,omitempty"`
	EntryCode  string     `json:"entry_code,omitempty"`
	SensorType string     `json:"sensor_type,omitempty"`
	// Ack is set when the entry was acknowledged.
	Ack *eventAckJSON `json:"ack,omitempty"`
}

type eventMeta struct {
	Total      int    `json:"total"`
	Limit      int    `json:"limit"`
	NextCursor string `json:"next_cursor,omitempty"`
	// Complete is false when the BMC log could not be read in full.
	Complete bool `json:"complete"`
	// Available is false until the log has been read at least once.
	Available bool   `json:"available"`
	Log       string `json:"log"`
}

// eventQuery is the validated query string.
type eventQuery struct {
	log    string
	since  time.Time
	limit  int
	cursor *position
}

// position is a keyset cursor: entries are ordered newest first by (Created, ID).
type position struct {
	created time.Time
	id      string
}

func (a *API) serverEvents(w http.ResponseWriter, r *http.Request) {
	s, ok := a.deps.Fleet.Server(r.PathValue("id"))
	if !ok {
		web.WriteProblem(w, r, http.StatusNotFound, "unknown server")
		return
	}
	q, msg := parseEventQuery(r)
	if msg != "" {
		web.WriteProblem(w, r, http.StatusBadRequest, msg)
		return
	}
	log, available := selectLog(s, q.log)
	page, meta := paginate(log, q)
	for i, e := range page {
		var created time.Time
		if e.Created != nil {
			created = *e.Created
		}
		page[i].Ack = a.eventAck(s.ID, q.log, bmc.Event{ID: e.ID, Created: created})
	}
	meta.Available, meta.Log = available, q.log
	writeJSON(w, http.StatusOK, list[eventJSON]{Data: page, Meta: meta})
}

func selectLog(s fleet.ServerState, which string) (bmc.EventLog, bool) {
	if which == logLifecycle {
		return s.Lifecycle, s.HasLifecycle
	}
	return s.SEL, s.HasSEL
}

// parseEventQuery validates ?log, ?since, ?limit and ?cursor. The returned message is
// safe to show; it never echoes the input.
func parseEventQuery(r *http.Request) (eventQuery, string) {
	v := r.URL.Query()
	q := eventQuery{log: cmp.Or(v.Get("log"), logSEL), limit: DefaultEventLimit}
	if q.log != logSEL && q.log != logLifecycle {
		return q, "log must be sel or lifecycle"
	}
	if raw := v.Get("since"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return q, "since must be an RFC 3339 timestamp"
		}
		q.since = t
	}
	if raw := v.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > MaxEventLimit {
			return q, "limit must be an integer from 1 to 200"
		}
		q.limit = n
	}
	if raw := v.Get("cursor"); raw != "" {
		p, ok := decodeCursor(raw)
		if !ok {
			return q, "cursor is invalid"
		}
		q.cursor = &p
	}
	return q, ""
}

func paginate(log bmc.EventLog, q eventQuery) ([]eventJSON, eventMeta) {
	entries := slices.DeleteFunc(log.Entries(), func(e bmc.Event) bool {
		return !q.since.IsZero() && !e.Created.After(q.since)
	})
	slices.SortStableFunc(entries, func(a, b bmc.Event) int { return -compareEvents(a, b) })
	meta := eventMeta{Total: len(entries), Limit: q.limit, Complete: log.Complete()}
	start := 0
	if q.cursor != nil {
		start, _ = slices.BinarySearchFunc(entries, *q.cursor, func(e bmc.Event, p position) int {
			return -compareEvents(e, bmc.Event{Created: p.created, ID: p.id})
		})
		for start < len(entries) && compareEvents(entries[start], bmc.Event{Created: q.cursor.created, ID: q.cursor.id}) == 0 {
			start++
		}
	}
	end := min(start+q.limit, len(entries))
	page := make([]eventJSON, 0, end-start)
	for _, e := range entries[start:end] {
		page = append(page, eventJSON{ID: e.ID, Created: timePtr(e.Created), Severity: string(e.Severity),
			Message: e.Message, MessageID: e.MessageID, EntryType: e.EntryType, EntryCode: e.EntryCode,
			SensorType: e.SensorType})
	}
	if end < len(entries) {
		last := entries[end-1]
		meta.NextCursor = encodeCursor(position{created: last.Created, id: last.ID})
	}
	return page, meta
}

// compareEvents orders by Created, then by numeric ID when both parse, else lexically.
func compareEvents(a, b bmc.Event) int {
	if c := a.Created.Compare(b.Created); c != 0 {
		return c
	}
	ai, aerr := strconv.ParseInt(a.ID, 10, 64)
	bi, berr := strconv.ParseInt(b.ID, 10, 64)
	if aerr == nil && berr == nil {
		return cmp.Compare(ai, bi)
	}
	return strings.Compare(a.ID, b.ID)
}

const maxCursorLen = 256

func encodeCursor(p position) string {
	ts := "z" // entries without a timestamp
	if !p.created.IsZero() {
		ts = strconv.FormatInt(p.created.UnixNano(), 10)
	}
	raw := ts + "|" + p.id
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeCursor(s string) (position, bool) {
	if len(s) > maxCursorLen {
		return position{}, false
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return position{}, false
	}
	ts, id, ok := strings.Cut(string(b), "|")
	if !ok {
		return position{}, false
	}
	if ts == "z" {
		return position{id: id}, true
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return position{}, false
	}
	return position{created: time.Unix(0, n).UTC(), id: id}, true
}

package ui

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
	"oob-manager/internal/maint"
)

// Acknowledgements (tech_doc §28): a warning or critical log entry can be acknowledged,
// one at a time or every unacknowledged one shown for a server. It stays listed with
// "Acked by X at T: comment"; it leaves Needs attention, the event counts and
// notifications. An entry is named by its log, BMC timestamp and BMC id ("ref"), so a
// new entry of the same kind is never acknowledged by an old acknowledgement.

// ackView is how an acknowledgement is shown.
type ackView struct {
	By, At, ISO, Comment string
}

// ackForm is what a page needs to offer Acknowledge buttons (nil: the user may not).
type ackForm struct {
	CSRF string
	Back string // where the POST returns to (a local path)
}

func msOf(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// refValue is the form value naming one entry: "<log>|<unix ms>|<entry id>".
func refValue(kind LogKind, e bmc.Event) string {
	return string(kind) + "|" + strconv.FormatInt(msOf(e.Created), 10) + "|" + e.ID
}

func parseRef(serverID, v string) (maint.EventRef, bool) {
	parts := strings.SplitN(v, "|", 3)
	if len(parts) != 3 || (parts[0] != string(LogSEL) && parts[0] != string(LogLifecycle)) {
		return maint.EventRef{}, false
	}
	ms, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || ms < 0 {
		return maint.EventRef{}, false
	}
	r := maint.EventRef{ServerID: serverID, Log: parts[0], EntryID: parts[2]}
	if ms > 0 {
		r.Created = time.UnixMilli(ms).UTC()
	}
	return r, maint.ValidRef(r) == nil
}

func refOf(serverID string, kind LogKind, e bmc.Event) maint.EventRef {
	return maint.EventRef{ServerID: serverID, Log: string(kind), EntryID: e.ID, Created: e.Created}
}

// acked reports whether an entry is acknowledged.
func (s *server) acked(serverID string, kind LogKind, e bmc.Event) (maint.Ack, bool) {
	if s.d.Maintenance == nil {
		return maint.Ack{}, false
	}
	return s.d.Maintenance.AckOf(refOf(serverID, kind, e))
}

// ackFormFor returns the form settings for a page, or nil when the user may not
// acknowledge (or acknowledgements are not wired).
func (s *server) ackFormFor(sess session, back string) *ackForm {
	if s.d.Maintenance == nil || !s.d.Maintenance.Available() ||
		s.d.Authorize(sess.id.Principal(), authz.EventAck, true) != nil {
		return nil
	}
	return &ackForm{CSRF: s.csrf.issue(formSettings, sessionBinding(sess.token)), Back: back}
}

// withAck adds the acknowledgement state of one rendered entry.
func (s *server) withAck(r eventRow, serverID string, kind LogKind, e bmc.Event, tf timeFmt) eventRow {
	r.ServerID = serverID
	if isProblem(e.Severity) && e.ID != "" {
		r.Ref = refValue(kind, e)
	}
	if a, ok := s.acked(serverID, kind, e); ok {
		r.Ack = &ackView{By: a.By, At: tf.full(a.At), ISO: isoUTC(a.At), Comment: a.Comment}
	}
	return r
}

// unackedRefs are the refs of the rows of serverID that can still be acknowledged (the
// "Acknowledge all shown" form).
func unackedRefs(rows []eventRow, serverID string) []string {
	var out []string
	for _, r := range rows {
		if r.Ref != "" && r.Ack == nil && r.ServerID == serverID {
			out = append(out, r.Ref)
		}
	}
	return out
}

// ackEvents acknowledges the entries named in the "ref" fields. Each must still be a
// warning or critical entry of the server's cached log.
func (s *server) ackEvents(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	v, ok := s.maintServer(w, r)
	if !ok {
		return
	}
	refs, ok := s.knownRefs(r.Context(), v.ID, form["ref"])
	if !ok {
		s.errorPage(w, r, http.StatusBadRequest, "These log entries are no longer in the server's log, or cannot be acknowledged.")
		return
	}
	if _, err := s.d.Maintenance.Ack(r.Context(), actor(r, sess), v.ID, refs, form.Get("comment")); err != nil {
		s.maintFailed(w, r, "acknowledge", err)
		return
	}
	redirectLocal(w, r, localPath(form.Get("back"), "/servers/"+v.ID+"/events"))
}

// unackEvent removes the acknowledgement of the one entry in "ref".
func (s *server) unackEvent(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	v, ok := s.maintServer(w, r)
	if !ok {
		return
	}
	ref, ok := parseRef(v.ID, form.Get("ref"))
	if !ok {
		s.errorPage(w, r, http.StatusBadRequest, "Unknown log entry.")
		return
	}
	if err := s.d.Maintenance.Unack(r.Context(), actor(r, sess), ref); err != nil {
		s.maintFailed(w, r, "unacknowledge", err)
		return
	}
	redirectLocal(w, r, localPath(form.Get("back"), "/servers/"+v.ID+"/events"))
}

// knownRefs parses values and keeps them only when every one names a warning or
// critical entry present in the server's cached log (duplicates folded).
func (s *server) knownRefs(ctx context.Context, serverID string, values []string) ([]maint.EventRef, bool) {
	if len(values) == 0 || len(values) > maint.MaxAcksPerRequest {
		return nil, false
	}
	logs := map[LogKind]map[string]bool{}
	seen := map[string]bool{}
	var out []maint.EventRef
	for _, v := range values {
		ref, ok := parseRef(serverID, v)
		if !ok {
			return nil, false
		}
		kind := LogKind(ref.Log)
		if logs[kind] == nil {
			logs[kind] = s.problemRefs(ctx, serverID, kind)
		}
		if !logs[kind][v] {
			return nil, false
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, ref)
		}
	}
	return out, true
}

func (s *server) problemRefs(ctx context.Context, serverID string, kind LogKind) map[string]bool {
	out := map[string]bool{}
	log, err := s.d.Fleet.Events(ctx, serverID, kind)
	if err != nil {
		return out
	}
	for _, e := range log.Entries() {
		if isProblem(e.Severity) && e.ID != "" {
			out[refValue(kind, e)] = true
		}
	}
	return out
}

// withAckForm hands the page's form settings to every row (templates take one value).
func withAckForm(rows []eventRow, f *ackForm) []eventRow {
	out := make([]eventRow, len(rows))
	for i, r := range rows {
		r.Form, r.Idx = f, i
		out[i] = r
	}
	return out
}

// ackAllView is the "Acknowledge all shown" form of one server.
type ackAllView struct {
	ServerID string
	Refs     []string
	Form     *ackForm
}

// ackAllOf offers the form when at least two rows of serverID can be acknowledged.
func ackAllOf(rows []eventRow, serverID string, f *ackForm) *ackAllView {
	refs := unackedRefs(rows, serverID)
	if f == nil || len(refs) < 2 {
		return nil
	}
	return &ackAllView{ServerID: serverID, Refs: refs, Form: f}
}

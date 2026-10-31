package ui

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/authz"
	"oob-manager/internal/maint"
)

// Maintenance is maintenance mode, server notes and event acknowledgements
// (*maint.Service, tech_doc §28). Every change it makes is audited; the UI authorizes
// before calling. Reads are lock-free.
type Maintenance interface {
	Available() bool
	Window(serverID string) (maint.Window, bool)
	Active(serverID string) (maint.Window, bool)
	// OpenEnded lists active "until ended" windows older than maint.OpenEndedAfter.
	OpenEnded() []maint.Window
	Start(ctx context.Context, a admin.Actor, serverID string, req maint.StartRequest) (maint.Window, error)
	End(ctx context.Context, a admin.Actor, serverID string) error
	Notes(serverID string) []maint.Note
	AddNote(ctx context.Context, a admin.Actor, serverID, body string) (maint.Note, error)
	EditNote(ctx context.Context, a admin.Actor, serverID string, id int64, body string) error
	DeleteNote(ctx context.Context, a admin.Actor, serverID string, id int64) error
	PinNote(ctx context.Context, a admin.Actor, serverID string, id int64) error
	AckOf(r maint.EventRef) (maint.Ack, bool)
	Ack(ctx context.Context, a admin.Actor, serverID string, refs []maint.EventRef, comment string) (int, error)
	Unack(ctx context.Context, a admin.Actor, r maint.EventRef) error
}

// maintRoutes are the per-server maintenance, note and acknowledgement changes. Each goes
// through annotate(): session, CSRF, role (operator; no step-up: these pause or
// annotate, they never act on a BMC), a per-user limit, and audit of every refusal.
func (s *server) maintRoutes(mux *http.ServeMux) {
	mux.Handle("GET /servers/{id}/maintenance/new", s.page(authz.ServerMaintenance, s.maintNewPage))
	mux.Handle("GET /servers/{id}/notes/new", s.page(authz.ServerNotes, s.noteNewPage))
	mux.Handle("GET /servers/{id}/notes/{nid}/edit", s.page(authz.ServerNotes, s.noteEditPage))
	mux.Handle("POST /servers/{id}/maintenance", s.annotate(authz.ServerMaintenance, backToServerPage, s.startMaintenance))
	mux.Handle("POST /servers/{id}/maintenance/end", s.annotate(authz.ServerMaintenance, backToServerPage, s.endMaintenance))
	mux.Handle("POST /servers/{id}/notes", s.annotate(authz.ServerNotes, backToServerPage, s.addNote))
	mux.Handle("POST /servers/{id}/notes/pin", s.annotate(authz.ServerNotes, backToServerPage, s.pinNote))
	mux.Handle("POST /servers/{id}/notes/{nid}", s.annotate(authz.ServerNotes, backToServerPage, s.editNote))
	mux.Handle("POST /servers/{id}/notes/{nid}/delete", s.annotate(authz.ServerNotes, backToServerPage, s.deleteNote))
	mux.Handle("POST /servers/{id}/acks", s.annotate(authz.EventAck, backToServerPage, s.ackEvents))
	mux.Handle("POST /servers/{id}/acks/remove", s.annotate(authz.EventAck, backToServerPage, s.unackEvent))
}

// maintChangeRate limits maintenance, note and acknowledgement changes per user: higher
// than the Settings limit (acknowledging a log one entry at a time is normal work).
var maintChangeRate = RateLimit{Events: 30, Per: time.Minute}

// annotate is change() with its own per-user limit (maintChangeRate).
func (s *server) annotate(action authz.Action, back func(*http.Request) string, h changeHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, form, ok := s.changeForm(w, r, action)
		if !ok || !s.authorizeChange(w, r, sess, action, back(r)) {
			return
		}
		if ok, wait := s.maintLimit.allow("user:" + sess.id.User.ID); !ok {
			s.deny(r, sess, action, "rate_limited")
			setRetryAfter(w, wait)
			s.errorPage(w, r, http.StatusTooManyRequests, "Too many changes in a short time. "+tryAgainIn(wait))
			return
		}
		h(w, r, sess, form)
	})
}

// maintServer resolves {id} for a maintenance change: a configured server and a wired
// service, or a 404 page.
func (s *server) maintServer(w http.ResponseWriter, r *http.Request) (ServerView, bool) {
	id := r.PathValue("id")
	if s.d.Maintenance != nil && s.d.Maintenance.Available() && serverIDPattern.MatchString(id) {
		if v, ok := s.d.Fleet.Server(id); ok {
			return v, true
		}
	}
	s.errorPage(w, r, http.StatusNotFound, "There is no such server.")
	return ServerView{}, false
}

// maintFailed maps a service error to a page. Validation messages are the service's
// own (safe to show); anything else is logged and answered generically.
func (s *server) maintFailed(w http.ResponseWriter, r *http.Request, what string, err error) {
	switch {
	case errors.Is(err, maint.ErrInvalid):
		s.errorPage(w, r, http.StatusUnprocessableEntity, invalidText(err))
	case errors.Is(err, maint.ErrExists):
		s.errorPage(w, r, http.StatusConflict, "This server already has a maintenance window. End it first.")
	case errors.Is(err, maint.ErrForbidden):
		s.errorPage(w, r, http.StatusForbidden, "Only the author of a note can change it (an admin can delete it).")
	case errors.Is(err, maint.ErrNotFound):
		s.errorPage(w, r, http.StatusNotFound, "It no longer exists.")
	default:
		s.d.Logger.Error("ui "+what+" failed", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "The change could not be saved. Nothing was changed.")
	}
}

// invalidText is the user-facing part of a maint.ErrInvalid error ("maint: invalid
// input: the reason is required" → "The reason is required.").
func invalidText(err error) string {
	msg := err.Error()
	const prefix = "maint: invalid input: "
	if i := len(prefix); len(msg) > i && msg[:i] == prefix {
		msg = msg[i:]
	}
	if msg == "" {
		return "Invalid input."
	}
	return upperFirst(msg) + "."
}

func upperFirst(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}

func parseNoteID(s string) (int64, bool) {
	id, err := strconv.ParseInt(s, 10, 64)
	return id, err == nil && id > 0
}

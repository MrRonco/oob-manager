package ui

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"oob-manager/internal/authz"
	"oob-manager/internal/maint"
)

// The maintenance and note forms are pages of their own (audit R2-02): the server page
// auto-refreshes when the user asks for it, and a refresh must never discard what was
// typed. A validation error re-renders the form with the values kept.

// maintForm is what the Start maintenance form carries (kept on a validation error).
type maintForm struct {
	Reason, Duration, EndsAt, StartsAt string
}

// maintFormView is the Start maintenance page.
type maintFormView struct {
	Head                 serverHead
	ServerID, ServerName string
	CSRF                 string
	Form                 maintForm
	Invalid              string // the field the error is about ("" = none)
	Error                string
	Durations            []kv
	MinStart, MaxStart   string // datetime-local bounds in the user's zone
	Zone                 string
	Badge                *maintBadge // an existing window: no form, the way back
}

// noteFormView is the Add note / Edit note page.
type noteFormView struct {
	Head     serverHead
	ServerID string
	CSRF     string
	Action   string // POST target
	Body     string
	Error    string
	Edit     bool
	MaxBytes int
}

func maintFormOf(form url.Values) maintForm {
	g := func(k string) string { return strings.TrimSpace(form.Get(k)) }
	return maintForm{Reason: g("reason"), Duration: form.Get("duration"), EndsAt: g("ends_at"), StartsAt: g("starts_at")}
}

// maintInvalidField names the form field a validation message is about.
func maintInvalidField(msg string) string {
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "reason"):
		return "reason"
	case strings.Contains(lower, "start"):
		return "starts_at"
	case strings.Contains(lower, "end"):
		return "ends_at"
	case strings.Contains(lower, "how long"), strings.Contains(lower, "duration"):
		return "duration"
	default:
		return ""
	}
}

// maintNewPage is GET /servers/{id}/maintenance/new (operator role, page() checks it).
func (s *server) maintNewPage(w http.ResponseWriter, r *http.Request, sess session) {
	v, ok := s.maintServer(w, r)
	if !ok {
		return
	}
	s.renderMaintForm(w, r, sess, v, http.StatusOK, maintForm{Duration: "1h"}, "")
}

func (s *server) renderMaintForm(w http.ResponseWriter, r *http.Request, sess session, v ServerView, status int, f maintForm, msg string) {
	tf, now := sess.tf(), s.d.Now()
	mv := maintFormView{Head: s.headFor(v, sess).tab("start maintenance"), ServerID: v.ID, ServerName: v.Name,
		CSRF: s.csrf.issue(formSettings, sessionBinding(sess.token)), Form: f, Error: msg, Invalid: maintInvalidField(msg),
		Zone: zoneLabel(now, tf.loc), MinStart: now.In(tf.loc).Format(datetimeLocal),
		MaxStart: now.Add(maint.MaxScheduleAhead).In(tf.loc).Format(datetimeLocal)}
	for _, d := range maintDurations {
		mv.Durations = append(mv.Durations, kv{d.Value, d.Label})
	}
	if wnd, ok := s.d.Maintenance.Window(v.ID); ok {
		mv.Badge = badgeOf(wnd, now, tf)
	}
	d := s.serverLayout(sess, v, v.Name+": start maintenance", "Maintenance", mv)
	s.render(w, r, status, pageMaintNew, d)
}

// noteNewPage is GET /servers/{id}/notes/new.
func (s *server) noteNewPage(w http.ResponseWriter, r *http.Request, sess session) {
	v, ok := s.maintServer(w, r)
	if !ok {
		return
	}
	s.renderNoteForm(w, r, sess, v, http.StatusOK, noteFormView{Action: "/servers/" + v.ID + "/notes"}, "")
}

// noteEditPage is GET /servers/{id}/notes/{nid}/edit: the author only (an admin deletes
// other people's notes, never rewrites them).
func (s *server) noteEditPage(w http.ResponseWriter, r *http.Request, sess session) {
	v, id, ok := s.noteTarget(w, r)
	if !ok {
		return
	}
	for _, n := range s.d.Maintenance.Notes(v.ID) {
		if n.ID != id {
			continue
		}
		if n.AuthorID != sess.id.User.ID {
			s.deny(r, sess, authz.ServerNotes, "forbidden")
			s.errorPage(w, r, http.StatusForbidden, "Only the author of a note can change it (an admin can delete it).")
			return
		}
		s.renderNoteForm(w, r, sess, v, http.StatusOK, noteFormView{Action: "/servers/" + v.ID + "/notes/" + strconv.FormatInt(id, 10),
			Body: n.Body, Edit: true}, "")
		return
	}
	s.errorPage(w, r, http.StatusNotFound, "There is no such note.")
}

func (s *server) renderNoteForm(w http.ResponseWriter, r *http.Request, sess session, v ServerView, status int, nv noteFormView, msg string) {
	title := "add a note"
	if nv.Edit {
		title = "edit note"
	}
	nv.Head, nv.ServerID, nv.Error, nv.MaxBytes = s.headFor(v, sess).tab(title), v.ID, msg, maint.MaxNoteBytes
	nv.CSRF = s.csrf.issue(formSettings, sessionBinding(sess.token))
	d := s.serverLayout(sess, v, v.Name+": "+title, "Notes", nv)
	s.render(w, r, status, pageNoteForm, d)
}

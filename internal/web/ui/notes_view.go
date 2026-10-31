package ui

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"oob-manager/internal/authz"
	"oob-manager/internal/maint"
)

// noteURL finds http(s) links in note text. Matches are re-checked with url.Parse and
// rendered by html/template (which escapes the text and filters the href), with
// rel="noopener noreferrer"; nothing else in a note is ever markup.
var noteURL = regexp.MustCompile(`https?://[^\s<>"'` + "`" + `]+`)

// noteSeg is a run of note text, linked when Href is set. Text keeps its newlines; the
// note body is rendered with white-space: pre-wrap.
type noteSeg struct{ Text, Href string }

// linkify splits plain text into text and link segments.
func linkify(body string) []noteSeg {
	var out []noteSeg
	last := 0
	for _, m := range noteURL.FindAllStringIndex(body, -1) {
		raw := strings.TrimRight(body[m[0]:m[1]], ".,;:!?)]}")
		end := m[0] + len(raw)
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			continue
		}
		if m[0] > last {
			out = append(out, noteSeg{Text: body[last:m[0]]})
		}
		out = append(out, noteSeg{Text: raw, Href: u.String()})
		last = end
	}
	if last < len(body) {
		out = append(out, noteSeg{Text: body[last:]})
	}
	return out
}

// noteView is one note as rendered.
type noteView struct {
	ID              int64
	Body            string // raw text, for the edit form only (escaped by the template)
	Segs            []noteSeg
	Author, At, ISO string
	Edited          string // "edited 21 Oct 10:02 EDT" or ""
	Pinned          bool
	CanEdit         bool // the viewer wrote it
	CanDelete       bool // the viewer wrote it, or is an admin
}

// notesCard is the Notes panel of a server page. Adding and editing are pages of
// their own (maint_pages.go), so the auto-refreshed server page never carries typed
// input (audit R2-02); pin and delete stay as button-only forms.
type notesCard struct {
	ServerID string
	Notes    []noteView
	CanWrite bool
	CSRF     string
}

func (s *server) notesFor(v ServerView, sess session) (*notesCard, *noteView) {
	if s.d.Maintenance == nil || !s.d.Maintenance.Available() {
		return nil, nil
	}
	p := sess.id.Principal()
	c := &notesCard{ServerID: v.ID, CanWrite: s.d.Authorize(p, authz.ServerNotes, true) == nil}
	moderate := s.d.Authorize(p, authz.ServerNotesModerate, true) == nil
	if c.CanWrite {
		c.CSRF = s.csrf.issue(formSettings, sessionBinding(sess.token))
	}
	var pinned *noteView
	tf := sess.tf()
	for _, n := range s.d.Maintenance.Notes(v.ID) {
		mine := c.CanWrite && n.AuthorID == sess.id.User.ID
		nv := noteView{ID: n.ID, Body: n.Body, Segs: linkify(n.Body), Author: n.Author, At: tf.full(n.CreatedAt),
			ISO: isoUTC(n.CreatedAt), Pinned: n.Pinned, CanEdit: mine, CanDelete: mine || (c.CanWrite && moderate)}
		if n.Edited() {
			nv.Edited = "edited " + tf.full(n.UpdatedAt)
		}
		if n.Pinned {
			pinned = &nv
		}
		c.Notes = append(c.Notes, nv)
	}
	return c, pinned
}

func (s *server) addNote(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	v, ok := s.maintServer(w, r)
	if !ok {
		return
	}
	body := form.Get("body")
	if _, err := s.d.Maintenance.AddNote(r.Context(), actor(r, sess), v.ID, body); err != nil {
		if errors.Is(err, maint.ErrInvalid) {
			s.renderNoteForm(w, r, sess, v, http.StatusUnprocessableEntity,
				noteFormView{Action: "/servers/" + v.ID + "/notes", Body: body}, invalidText(err))
			return
		}
		s.maintFailed(w, r, "note add", err)
		return
	}
	http.Redirect(w, r, "/servers/"+v.ID+"/activity#notes", http.StatusSeeOther)
}

func (s *server) editNote(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	v, id, ok := s.noteTarget(w, r)
	if !ok {
		return
	}
	body := form.Get("body")
	if err := s.d.Maintenance.EditNote(r.Context(), actor(r, sess), v.ID, id, body); err != nil {
		if errors.Is(err, maint.ErrInvalid) {
			s.renderNoteForm(w, r, sess, v, http.StatusUnprocessableEntity,
				noteFormView{Action: "/servers/" + v.ID + "/notes/" + strconv.FormatInt(id, 10), Body: body, Edit: true}, invalidText(err))
			return
		}
		s.maintFailed(w, r, "note edit", err)
		return
	}
	http.Redirect(w, r, "/servers/"+v.ID+"#note-"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

func (s *server) deleteNote(w http.ResponseWriter, r *http.Request, sess session, _ url.Values) {
	v, id, ok := s.noteTarget(w, r)
	if !ok {
		return
	}
	if err := s.d.Maintenance.DeleteNote(r.Context(), actor(r, sess), v.ID, id); err != nil {
		s.maintFailed(w, r, "note delete", err)
		return
	}
	http.Redirect(w, r, "/servers/"+v.ID+"/activity#notes", http.StatusSeeOther)
}

// pinNote pins the note in the "note" field ("0" unpins).
func (s *server) pinNote(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	v, ok := s.maintServer(w, r)
	if !ok {
		return
	}
	id, ok := parseNoteID(form.Get("note"))
	if form.Get("note") == "0" {
		id, ok = 0, true
	}
	if !ok {
		s.errorPage(w, r, http.StatusBadRequest, "Unknown note.")
		return
	}
	if err := s.d.Maintenance.PinNote(r.Context(), actor(r, sess), v.ID, id); err != nil {
		s.maintFailed(w, r, "note pin", err)
		return
	}
	http.Redirect(w, r, "/servers/"+v.ID+"/activity#notes", http.StatusSeeOther)
}

func (s *server) noteTarget(w http.ResponseWriter, r *http.Request) (ServerView, int64, bool) {
	v, ok := s.maintServer(w, r)
	if !ok {
		return ServerView{}, 0, false
	}
	id, ok := parseNoteID(r.PathValue("nid"))
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "There is no such note.")
		return ServerView{}, 0, false
	}
	return v, id, true
}

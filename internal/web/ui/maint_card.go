package ui

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"oob-manager/internal/authz"
	"oob-manager/internal/maint"
)

// maintDurations is the closed set of window lengths offered (0 = until ended; custom
// takes the end time from the form).
var maintDurations = []struct {
	Value, Label string
	D            time.Duration
}{
	{"30m", "30 minutes", 30 * time.Minute}, {"1h", "1 hour", time.Hour}, {"4h", "4 hours", 4 * time.Hour},
	{"24h", "24 hours", 24 * time.Hour}, {"custom", "Until a time I choose (at most 7 days)", -1},
	{"until", "Until I end it", 0},
}

// datetimeLocal is the value format of <input type=datetime-local>, read in the user's
// display time zone.
const datetimeLocal = "2006-01-02T15:04"

// maintBadge is "In maintenance until … — reason — by user" (Overview, sidebar, server
// pages). Scheduled marks a window that has not begun yet (server page only).
type maintBadge struct {
	Reason, By           string
	Until, UntilISO      string // "" when the window lasts until it is ended
	Starts, StartsISO    string
	Scheduled, UntilEnds bool
}

// Text is the badge as one sentence (also the sidebar title).
func (b maintBadge) Text() string {
	var when string
	switch {
	case b.Scheduled && b.UntilEnds:
		when = "Maintenance from " + b.Starts + " until ended"
	case b.Scheduled:
		when = "Maintenance from " + b.Starts + " until " + b.Until
	case b.UntilEnds:
		when = "In maintenance until ended"
	default:
		when = "In maintenance until " + b.Until
	}
	return when + " — " + b.Reason + " — by " + b.By
}

func badgeOf(w maint.Window, now time.Time, tf timeFmt) *maintBadge {
	b := &maintBadge{Reason: w.Reason, By: w.By, Scheduled: w.ScheduledAt(now), UntilEnds: w.UntilEnded(),
		Starts: tf.full(w.StartsAt), StartsISO: isoUTC(w.StartsAt)}
	if !w.UntilEnded() {
		b.Until, b.UntilISO = tf.full(w.EndsAt), isoUTC(w.EndsAt)
	}
	return b
}

// activeBadge is the badge of a server whose window is active now (nil otherwise).
func (s *server) activeBadge(serverID string, tf timeFmt) *maintBadge {
	if s.d.Maintenance == nil {
		return nil
	}
	w, ok := s.d.Maintenance.Active(serverID)
	if !ok {
		return nil
	}
	return badgeOf(w, s.d.Now(), tf)
}

// maintCard is the Maintenance panel of a server page: the window and the way to end
// it. Starting one is its own page (maint_pages.go), so the auto-refreshed server page
// never carries typed input (audit R2-02).
type maintCard struct {
	ServerID, ServerName string
	Badge                *maintBadge // active or scheduled window
	CanChange            bool
	CSRF                 string
}

func (s *server) maintCardFor(v ServerView, sess session) *maintCard {
	if s.d.Maintenance == nil || !s.d.Maintenance.Available() {
		return nil
	}
	c := &maintCard{ServerID: v.ID, ServerName: v.Name,
		CanChange: s.d.Authorize(sess.id.Principal(), authz.ServerMaintenance, true) == nil}
	if w, ok := s.d.Maintenance.Window(v.ID); ok {
		c.Badge = badgeOf(w, s.d.Now(), sess.tf())
	}
	if c.CanChange {
		c.CSRF = s.csrf.issue(formSettings, sessionBinding(sess.token))
	}
	return c
}

// startMaintenance opens or schedules a window. The duration is a closed set; custom
// end and optional start times are read in the user's display zone. Invalid input
// re-renders the form with the values kept.
func (s *server) startMaintenance(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	v, ok := s.maintServer(w, r)
	if !ok {
		return
	}
	req, msg := maintRequest(form, sess.tf().loc, s.d.Now())
	if msg == "" {
		_, err := s.d.Maintenance.Start(r.Context(), actor(r, sess), v.ID, req)
		if err == nil {
			http.Redirect(w, r, "/servers/"+v.ID+"/activity#maint", http.StatusSeeOther)
			return
		}
		if !errors.Is(err, maint.ErrInvalid) {
			s.maintFailed(w, r, "maintenance start", err)
			return
		}
		msg = invalidText(err)
	}
	s.renderMaintForm(w, r, sess, v, http.StatusUnprocessableEntity, maintFormOf(form), msg)
}

func maintRequest(form url.Values, loc *time.Location, now time.Time) (maint.StartRequest, string) {
	req := maint.StartRequest{Reason: form.Get("reason")}
	if v := strings.TrimSpace(form.Get("starts_at")); v != "" {
		t, err := time.ParseInLocation(datetimeLocal, v, loc)
		if err != nil {
			return req, "Enter the start as a date and time, or leave it empty to start now."
		}
		req.StartsAt = t
	}
	choice := form.Get("duration")
	for _, d := range maintDurations {
		if d.Value != choice {
			continue
		}
		if d.D >= 0 {
			req.Duration = d.D
			return req, ""
		}
		end, err := time.ParseInLocation(datetimeLocal, strings.TrimSpace(form.Get("ends_at")), loc)
		if err != nil {
			return req, "Enter when the maintenance ends."
		}
		start := now
		if !req.StartsAt.IsZero() {
			start = req.StartsAt
		}
		if req.Duration = end.Sub(start); req.Duration <= 0 {
			return req, "The end must be after the start."
		}
		return req, ""
	}
	return req, "Choose how long the maintenance lasts."
}

// endMaintenance ends the window now (or cancels a scheduled one).
func (s *server) endMaintenance(w http.ResponseWriter, r *http.Request, sess session, _ url.Values) {
	v, ok := s.maintServer(w, r)
	if !ok {
		return
	}
	if err := s.d.Maintenance.End(r.Context(), actor(r, sess), v.ID); err != nil {
		s.maintFailed(w, r, "maintenance end", err)
		return
	}
	http.Redirect(w, r, "/servers/"+v.ID+"/activity#maint", http.StatusSeeOther)
}

// inMaintenance reports whether a server's window is active now.
func (s *server) inMaintenance(serverID string) bool {
	if s.d.Maintenance == nil {
		return false
	}
	_, ok := s.d.Maintenance.Active(serverID)
	return ok
}

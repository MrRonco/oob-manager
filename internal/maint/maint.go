// Package maint keeps the per-server operational state people add on top of what the
// BMCs report (docs/tech_doc.md §28):
//
//   - maintenance windows: while one is active the server's warnings are shown but not
//     counted in the fleet verdict, and its health, reachability, log and PSU
//     notifications are suppressed (security-class notifications are never suppressed);
//   - plain-text notes, one of them optionally pinned to the top of the server page;
//   - acknowledgements of BMC log entries, which take them out of "Needs attention" and
//     out of notifications without hiding them.
//
// Every change is one transaction with its audit row. Reads are lock-free loads of an
// immutable state published through an atomic.Pointer. Nothing here reaches a BMC.
package maint

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Limits.
const (
	MaxWindow         = 7 * 24 * time.Hour  // longest timed window
	MinWindow         = 5 * time.Minute     // shortest custom window
	MaxScheduleAhead  = 30 * 24 * time.Hour // furthest a window may be scheduled
	MaxReasonRunes    = 200
	MaxNoteBytes      = 4096
	MaxCommentBytes   = 500
	MaxNotesPerServer = 100
	MaxAcksPerRequest = 500
	MaxEntryIDBytes   = 128
	// AckRetention is how long an acknowledgement is kept (BMC logs rarely hold a year).
	AckRetention = 400 * 24 * time.Hour
	// OpenEndedAfter is how long an "until ended" window runs before Overview warns
	// about it, and the interval of its reminder notifications (design decision, §30).
	OpenEndedAfter = 24 * time.Hour
)

// Log names an acknowledgement can refer to.
const (
	LogSEL       = "sel"
	LogLifecycle = "lifecycle"
)

// Audit actions.
const (
	ActionStart      = "server.maintenance.start"
	ActionEnd        = "server.maintenance.end"
	ActionNoteAdd    = "server.note.add"
	ActionNoteEdit   = "server.note.edit"
	ActionNoteDelete = "server.note.delete"
	ActionNotePin    = "server.note.pin"
	ActionAck        = "server.event.ack"
	ActionUnack      = "server.event.unack"
)

// Errors. Messages are safe to show to the user.
var (
	ErrInvalid     = errors.New("maint: invalid input")
	ErrNotFound    = errors.New("maint: not found")
	ErrForbidden   = errors.New("maint: only the author (or an admin, to delete) may change this note")
	ErrExists      = errors.New("maint: this server already has a maintenance window; end it first")
	ErrUnavailable = errors.New("maint: not available without a database")
)

// Window is a server's maintenance window. A zero EndsAt means "until ended".
type Window struct {
	ServerID  string
	StartsAt  time.Time
	EndsAt    time.Time
	Reason    string
	By        string
	CreatedAt time.Time
	// Notified: the "maintenance started" notification went out.
	Notified bool
	// RemindedAt is when the last open-ended reminder went out (zero: none yet).
	RemindedAt time.Time
}

// ActiveAt reports whether the window covers t.
func (w Window) ActiveAt(t time.Time) bool {
	return !t.Before(w.StartsAt) && (w.EndsAt.IsZero() || t.Before(w.EndsAt))
}

// ScheduledAt reports whether the window starts after t.
func (w Window) ScheduledAt(t time.Time) bool { return t.Before(w.StartsAt) }

// ExpiredAt reports whether a timed window is over at t.
func (w Window) ExpiredAt(t time.Time) bool { return !w.EndsAt.IsZero() && !t.Before(w.EndsAt) }

// UntilEnded reports a window without an end time.
func (w Window) UntilEnded() bool { return w.EndsAt.IsZero() }

// LongOpenEndedAt reports an active "until ended" window that began at least
// OpenEndedAfter before t (Overview warns about it).
func (w Window) LongOpenEndedAt(t time.Time) bool {
	return w.UntilEnded() && w.ActiveAt(t) && t.Sub(w.StartsAt) >= OpenEndedAfter
}

// ReminderDueAt reports whether a long open-ended window owes its daily reminder at t:
// OpenEndedAfter since the start, then since the last reminder.
func (w Window) ReminderDueAt(t time.Time) bool {
	last := w.StartsAt
	if w.RemindedAt.After(last) {
		last = w.RemindedAt
	}
	return w.Notified && w.LongOpenEndedAt(t) && t.Sub(last) >= OpenEndedAfter
}

// StartRequest is a new window. Duration 0 means "until ended"; a zero StartsAt starts now.
type StartRequest struct {
	Reason   string
	Duration time.Duration
	StartsAt time.Time
}

// Note is one plain-text note on a server.
type Note struct {
	ID        int64
	ServerID  string
	Body      string
	Pinned    bool
	AuthorID  string
	Author    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Edited reports whether the note was changed after it was written.
func (n Note) Edited() bool { return n.UpdatedAt.After(n.CreatedAt) }

// EventRef identifies one BMC log entry stably across polls: the server, the log, the
// BMC's entry id and its BMC timestamp (zero when the BMC sent none).
type EventRef struct {
	ServerID string
	Log      string
	EntryID  string
	Created  time.Time
}

// key is the map key of a reference (unix ms, as stored).
func (r EventRef) key() string {
	return r.ServerID + "\x00" + r.Log + "\x00" + r.EntryID + "\x00" + strconv.FormatInt(createdMS(r.Created), 10)
}

func createdMS(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromCreatedMS(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

// Ack is an acknowledged log entry.
type Ack struct {
	Ref     EventRef
	Comment string
	By      string
	At      time.Time
}

// CleanReason validates a maintenance reason: one line of printable text, 1–200 characters.
func CleanReason(s string) (string, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return "", fmt.Errorf("%w: a reason is required", ErrInvalid)
	case !utf8.ValidString(s) || strings.ContainsFunc(s, unicode.IsControl):
		return "", fmt.Errorf("%w: the reason must be one line of text", ErrInvalid)
	case utf8.RuneCountInString(s) > MaxReasonRunes:
		return "", fmt.Errorf("%w: the reason is limited to %d characters", ErrInvalid, MaxReasonRunes)
	}
	return s, nil
}

// CleanNote validates a note: plain text (newlines and tabs kept, CRLF → LF, other
// control characters refused), not empty, at most 4 KiB.
func CleanNote(s string) (string, error) {
	s = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n"))
	switch {
	case s == "":
		return "", fmt.Errorf("%w: the note is empty", ErrInvalid)
	case !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }):
		return "", fmt.Errorf("%w: the note contains control characters", ErrInvalid)
	case len(s) > MaxNoteBytes:
		return "", fmt.Errorf("%w: a note is limited to %d bytes (it has %d)", ErrInvalid, MaxNoteBytes, len(s))
	}
	return s, nil
}

// CleanComment validates an optional acknowledgement comment (one line, ≤ 500 bytes).
func CleanComment(s string) (string, error) {
	s = strings.TrimSpace(s)
	switch {
	case !utf8.ValidString(s) || strings.ContainsFunc(s, unicode.IsControl):
		return "", fmt.Errorf("%w: the comment must be one line of text", ErrInvalid)
	case len(s) > MaxCommentBytes:
		return "", fmt.Errorf("%w: a comment is limited to %d bytes", ErrInvalid, MaxCommentBytes)
	}
	return s, nil
}

// ValidRef checks the shape of a reference (the caller checks that the entry exists).
func ValidRef(r EventRef) error {
	switch {
	case r.ServerID == "" || len(r.ServerID) > 64:
		return fmt.Errorf("%w: unknown server", ErrInvalid)
	case r.Log != LogSEL && r.Log != LogLifecycle:
		return fmt.Errorf("%w: unknown log", ErrInvalid)
	case r.EntryID == "" || len(r.EntryID) > MaxEntryIDBytes || !utf8.ValidString(r.EntryID) ||
		strings.ContainsFunc(r.EntryID, unicode.IsControl):
		return fmt.Errorf("%w: unknown log entry", ErrInvalid)
	}
	return nil
}

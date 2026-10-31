package ui

import (
	"fmt"
	"time"

	"oob-manager/internal/display"
)

// Time formats. Every rendered time carries a <time datetime> with the RFC 3339 instant;
// the visible text is short (direction B: "10:31", "Oct 20 04:44") with the zone shown
// once per page (the clock in the top bar) and in full in title attributes.

// timeFmt renders instants for one viewer: their zone (with its abbreviation, EDT/EST),
// date order and 12/24-hour clock. The machine-readable UTC instant always goes in
// <time datetime> separately. A value; build it with fmtFor.
type timeFmt struct {
	loc   *time.Location
	date  display.DateFormat
	clock display.ClockFormat
}

// fmtFor is the time format of a resolved display view.
func fmtFor(v display.View) timeFmt {
	loc := v.Loc
	if loc == nil {
		loc = time.UTC
	}
	return timeFmt{loc: loc, date: v.Date, clock: v.Clock}
}

// fmtIn is the default format (ISO date, 24-hour clock) in loc.
func fmtIn(loc *time.Location) timeFmt {
	return timeFmt{loc: loc, date: display.DateISO, clock: display.Clock24}
}

func (f timeFmt) hms() string {
	if f.clock == display.Clock12 {
		return "3:04:05 PM"
	}
	return "15:04:05"
}

func (f timeFmt) hm() string {
	if f.clock == display.Clock12 {
		return "3:04 PM"
	}
	return "15:04"
}

func (f timeFmt) ymd() string {
	if f.date == display.DateUS {
		return "01/02/2006"
	}
	return "2006-01-02"
}

// full is date, time with seconds and zone: "2026-10-21 14:05:09 EDT" or
// "10/21/2026 2:05:09 PM EDT"; zero time is "".
func (f timeFmt) full(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.In(f.loc).Format(f.ymd() + " " + f.hms() + " MST")
}

// clockOf is the top bar clock: "10:44:15 EDT" or "10:44:15 AM EDT".
func (f timeFmt) clockOf(t time.Time) string { return t.In(f.loc).Format(f.hms() + " MST") }

// short is "10:31" on the same local day as now, else "Oct 20 04:44"; zero is "".
func (f timeFmt) short(t, now time.Time) string {
	if t.IsZero() {
		return ""
	}
	lt, ln := t.In(f.loc), now.In(f.loc)
	if sameDay(lt, ln) {
		return lt.Format(f.hm())
	}
	return lt.Format("Jan 2 " + f.hm())
}

// fmtClock is the top bar clock in loc (24 h): "10:44:15 EDT".
func fmtClock(t time.Time, loc *time.Location) string { return fmtIn(loc).clockOf(t) }

// fmtShort is timeFmt.short in loc with a 24-hour clock.
func fmtShort(t, now time.Time, loc *time.Location) string { return fmtIn(loc).short(t, now) }

func sameDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

// fmtRel is the relative age of t at now: "just now", "13 min ago", "2 h ago",
// "yesterday", "3 days ago". Future times read "just now".
func fmtRel(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	case d < 48*time.Hour:
		return "yesterday"
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours())/24)
	}
}

// dayLabel names the local day of t for event day separators.
func dayLabel(t, now time.Time, loc *time.Location) string {
	if t.IsZero() {
		return "No time recorded"
	}
	lt, ln := t.In(loc), now.In(loc)
	switch {
	case sameDay(lt, ln):
		return "Today, " + lt.Format("Jan 2")
	case sameDay(lt, ln.AddDate(0, 0, -1)):
		return "Yesterday, " + lt.Format("Jan 2")
	case lt.Year() != ln.Year():
		return lt.Format("Mon, Jan 2 2006")
	default:
		return lt.Format("Mon, Jan 2")
	}
}

// fmtAge renders a duration coarsely: "42 s", "3 min", "2 h 5 min", "3 d 4 h".
func fmtAge(d time.Duration) string {
	d = max(d, 0).Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 24*time.Hour:
		if m := int(d.Minutes()) % 60; m != 0 {
			return fmt.Sprintf("%d h %d min", int(d.Hours()), m)
		}
		return fmt.Sprintf("%d h", int(d.Hours()))
	default:
		return fmt.Sprintf("%d d %d h", int(d.Hours())/24, int(d.Hours())%24)
	}
}

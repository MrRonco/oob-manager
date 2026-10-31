package ui

import (
	"context"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/display"
)

// pillView is the fleet verdict in the top bar ("1 warning · 1 stale"). The state's
// icon comes from Class (the "sicon" partial).
type pillView struct {
	Class, Text string
	// Short replaces Text on phones (screen readers still get Text); "" = Text fits.
	Short string
	// Empty: no server is configured (the favicon stays the plain mark).
	Empty bool
}

// clockView is the top bar clock: when the page was generated and how old the oldest
// current data is (the pill already counts stale servers).
type clockView struct {
	Time, ISO string
	Zone      string // IANA name of the zone shown (title of the clock link)
	DataAge   string // "15 s"; "" when no server has current data
}

// fleetCounts tallies servers by state; stale and never-polled servers are counted as
// stale only, so a server is never both "stale" and "warning".
type fleetCounts struct {
	Total, Critical, Warning, Unknown, Stale, OK int
	// Restarting counts servers whose BMC the app restarted and waits for (not stale).
	Restarting int
	// Off counts servers whose host is powered off, powering off or powering on (a
	// critical-tagged server that is off unexpectedly counts as Critical instead).
	Off int
	// Maintenance counts servers in a maintenance window, whatever their state: they
	// are not in any other count (tech_doc §28).
	Maintenance int
}

func countFleet(rows []summaryRow) fleetCounts {
	c := fleetCounts{Total: len(rows)}
	for _, r := range rows {
		switch fleetClass(r) {
		case "maint":
			c.Maintenance++
		case "restarting":
			c.Restarting++
		case "stale":
			c.Stale++
		case "critical":
			c.Critical++
		case "off":
			c.Off++
		case "warning":
			c.Warning++
		case "ok":
			c.OK++
		default:
			c.Unknown++
		}
	}
	return c
}

// fleetClass is the one state a server is counted under (the pill's words; the
// Overview hero names its worst server by the same rule).
func fleetClass(r summaryRow) string {
	switch {
	case r.Maint != nil:
		return "maint"
	case r.Fresh.Restarting:
		return "restarting"
	case r.Fresh.Stale:
		return "stale"
	case r.Health.Class == "crit":
		return "critical"
	case r.Health.Class == "off":
		return "off"
	case r.Health.Class == "warn":
		return "warning"
	case r.Health.Class == "ok":
		return "ok"
	default:
		return "unknown"
	}
}

func (p pillView) withText(t string) pillView { p.Text = t; return p.short() }

// Favicon names the status favicon (static/favicon-<state>.svg) for the fleet's worst
// state, so a background tab shows it (round-2 slice B, tech_doc §40): ok, warn, crit,
// stale or off. Maintenance alone is not an alarm (ok); unknown has no current data
// (stale). "" (no pill, or no server configured) keeps the plain mark.
func (p pillView) Favicon() string {
	if p.Class == "" || p.Empty {
		return ""
	}
	switch p.Class {
	case "gp-crit":
		return "crit"
	case "gp-warn":
		return "warn"
	case "gp-off":
		return "off"
	case "gp-ok", "gp-maint":
		return "ok"
	default: // gp-stale, gp-unknown
		return "stale"
	}
}

// short is the pill's phone text (plan 04 §11 item 9): only the worst part ("1 critical"
// of "1 critical · 1 stale", "1 off" of "2 OK · 1 off"), with maintenance shortened;
// screen readers still get the whole text.
func (p pillView) short() pillView {
	parts := strings.Split(p.Text, " · ")
	worst := parts[0]
	if len(parts) > 1 && strings.HasSuffix(worst, " OK") {
		worst = parts[1]
	}
	if worst = strings.ReplaceAll(worst, " in maintenance", " maint."); worst != p.Text {
		p.Short = worst
	}
	return p
}

// pillKind is one counted state in the pill, worst first.
type pillKind struct {
	n           int
	word, class string
}

// pillKinds lists the counted states worst first; stale comes before off so a pill with
// both ("1 stale · 1 off") takes the stale class (and icon) and never hides stale data.
func pillKinds(c fleetCounts) []pillKind {
	return []pillKind{
		{c.Critical, "critical", "gp-crit"}, {c.Warning, "warning", "gp-warn"}, {c.Stale, "stale", "gp-stale"},
		{c.Restarting, "restarting", "gp-stale"}, {c.Off, "off", "gp-off"}, {c.Unknown, "unknown", "gp-unknown"},
	}
}

func pillOf(c fleetCounts) pillView {
	var parts []string
	worst := pillView{Class: "gp-unknown"}
	for _, k := range pillKinds(c) {
		if k.n == 0 {
			continue
		}
		if len(parts) == 0 {
			worst = pillView{Class: k.class}
		}
		parts = append(parts, strconv.Itoa(k.n)+" "+k.word)
	}
	switch {
	case c.Total == 0:
		return pillView{Class: "gp-unknown", Text: "No servers", Empty: true}
	case len(parts) == 0 && c.Maintenance == c.Total:
		return pillView{Class: "gp-maint", Text: "All " + strconv.Itoa(c.Total) + " in maintenance"}.short()
	case len(parts) == 0 && c.Maintenance > 0:
		return pillView{Class: "gp-maint", Text: strconv.Itoa(c.OK) + " OK · " + strconv.Itoa(c.Maintenance) + " in maintenance"}.short()
	case len(parts) == 0:
		return pillView{Class: "gp-ok", Text: "All " + strconv.Itoa(c.Total) + " OK"}
	}
	if c.Off > 0 && len(parts) == 1 && c.OK > 0 {
		parts = []string{strconv.Itoa(c.OK) + " OK", parts[0]} // "2 OK · 1 off": off is not an alarm
	}
	if c.Maintenance > 0 {
		parts = append(parts, strconv.Itoa(c.Maintenance)+" in maintenance")
	}
	return worst.withText(strings.Join(parts, " · "))
}

// chrome builds the sidebar entries, the fleet pill and the clock's data age.
func (s *server) chrome(views []ServerView, vw display.View) ([]navEntry, pillView, string) {
	rows := make([]summaryRow, 0, len(views))
	entries := make([]navEntry, 0, len(views))
	oldest := time.Duration(-1)
	for _, v := range views {
		row := s.summarize(v, vw)
		rows = append(rows, row)
		entry := navEntry{ID: v.ID, Name: v.Name, Health: row.Health, Value: sideValue(row)}
		if row.Maint != nil {
			entry.Maint = row.Maint.Text()
		}
		entries = append(entries, entry)
		if !row.Fresh.Stale {
			oldest = max(oldest, s.d.Now().Sub(v.LastSuccess))
		}
	}
	age := ""
	if oldest >= 0 {
		age = fmtAge(oldest)
	}
	return entries, pillOf(countFleet(rows)), age
}

// sideValue is the sub-line under a server's name in the sidebar and the Menu sheet:
// what to know at a glance, in words. A maintenance window and a powered-off host are
// named, never shown by an icon alone (round-2 slice C).
func sideValue(row summaryRow) string {
	v := ""
	switch {
	case row.Fresh.Restarting:
		v = "BMC restarting"
	case row.Fresh.NoData:
		v = "No data"
	case row.Fresh.Stale:
		v = "Stale · " + row.Fresh.Age
	case row.HostDown:
		v = "Powered off"
	case row.Hottest.Value != "":
		v = row.Hottest.Value + " " + row.Hottest.Unit
	}
	switch {
	case row.Maint != nil && v == "":
		return "Maintenance"
	case row.Maint != nil: // a window is named whatever else the line says
		return "Maintenance · " + v
	}
	return v
}

// recentWindow is the "last 24 hours" of the attention list and the Events count.
const recentWindow = 24 * time.Hour

// recentEventCount counts unacknowledged warning and critical log entries of the last 24
// hours across the fleet, leaving out servers in maintenance. Logs are the pollers' cached copies, so this never reaches a BMC.
func (s *server) recentEventCount(views []ServerView) int {
	since := s.d.Now().Add(-recentWindow)
	n := 0
	for _, v := range views {
		if s.inMaintenance(v.ID) {
			continue
		}
		for _, kind := range []LogKind{LogSEL, LogLifecycle} {
			log, err := s.d.Fleet.Events(context.Background(), v.ID, kind)
			if err != nil {
				continue
			}
			for _, e := range log.Entries() {
				if _, acked := s.acked(v.ID, kind, e); !acked && isProblem(e.Severity) && e.Created.After(since) {
					n++
				}
			}
		}
	}
	return n
}

func isProblem(sev bmc.Severity) bool {
	return sev == bmc.SeverityWarning || sev == bmc.SeverityCritical
}

// themeForm is the theme switch in the user menu: a POST form that cycles Auto → Dark →
// Light, so it works without JavaScript.
type themeForm struct {
	CSRF, Next       string
	Label, NextValue string
	NextLabel        string
}

// themeCookie holds the per-browser theme ("dark" or "light"); absent = follow the OS.
const themeCookie = "__Host-oob_theme"

func themeFrom(c string) string {
	if c == "dark" || c == "light" {
		return c
	}
	return ""
}

func themeCycle(current string) themeForm {
	switch current {
	case "dark":
		return themeForm{Label: "Dark", NextValue: "light", NextLabel: "Light"}
	case "light":
		return themeForm{Label: "Light", NextValue: "auto", NextLabel: "Auto (follow the system)"}
	default:
		return themeForm{Label: "Auto", NextValue: "dark", NextLabel: "Dark"}
	}
}

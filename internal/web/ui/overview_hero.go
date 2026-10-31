package ui

import (
	"strconv"
	"strings"
)

// heroView is the Overview's verdict-first hero (round-2 slice C, direction A): the fleet
// verdict in one sentence, the worst item with its badge, the counts and the data age,
// then everything else that needs attention. Incident (B's incident mode) is set only
// while a server is critical: the verdict gets display type, the critical count a display
// numeral, and the icon tile one restrained glow. Nothing moves.
type heroView struct {
	Tone     string // the fleet's worst state class (ok, warn, crit, stale, off, maint, unknown)
	Title    string
	Worst    *attentionItem
	Also     []attentionItem
	Counts   []string // "1 critical", "1 stale", "2 OK"
	Incident bool
	Critical int
}

func heroOf(v overviewView) heroView {
	h := heroView{Tone: strings.TrimPrefix(pillOf(v.Counts).Class, "gp-"), Counts: heroCounts(v.Counts),
		Incident: v.Counts.Critical > 0, Critical: v.Counts.Critical}
	if len(v.Attention) > 0 {
		first := v.Attention[0]
		h.Worst, h.Also = &first, v.Attention[1:]
	}
	h.Title = heroTitle(v)
	if h.Tone == "ok" && len(v.Attention) > 0 { // only warning events: not an all-clear
		h.Tone = "warn"
	}
	return h
}

// heroTitle is the verdict: all healthy, else the first server of the pill's worst
// state (fleetClass, the rule the counts, the tone and incident mode follow), else the
// events that need attention.
func heroTitle(v overviewView) string {
	c := v.Counts
	switch {
	case v.Healthy && c.Maintenance > 0:
		return "All other servers healthy"
	case v.Healthy:
		return "All " + strconv.Itoa(c.Total) + " servers healthy"
	}
	for _, k := range pillKinds(c) { // the pill's worst word names the server
		for _, r := range v.Servers {
			if k.n > 0 && fleetClass(r) == k.word {
				return r.Name + ": " + r.Health.Label
			}
		}
	}
	switch {
	case len(v.Attention) > 0:
		return "Warning or critical events in the last 24 h"
	case c.Total > 0 && c.Maintenance == c.Total:
		return "All " + strconv.Itoa(c.Total) + " servers in maintenance"
	}
	return pillOf(c).Text
}

// heroCounts lists every counted state, worst first, then OK.
func heroCounts(c fleetCounts) []string {
	var out []string
	for _, k := range pillKinds(c) {
		if k.n > 0 {
			out = append(out, strconv.Itoa(k.n)+" "+k.word)
		}
	}
	if c.Maintenance > 0 {
		out = append(out, strconv.Itoa(c.Maintenance)+" in maintenance")
	}
	if c.OK > 0 {
		out = append(out, strconv.Itoa(c.OK)+" OK")
	}
	return out
}

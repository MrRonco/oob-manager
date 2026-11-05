package ui

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/history"
)

// TestOverviewHeroIsVerdictFirst (round-2 slice C): the hero names the fleet's verdict,
// leads with the worst item, and carries the counts and the data age.
func TestOverviewHeroIsVerdictFirst(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t)
	r := result(c.get("/")).status(t, http.StatusOK)
	r.contains(t, `class="hero hero-stale" id="verdict"`, `<span class="eyebrow">Overview</span>`,
		`<span class="hero-t verdict">Edge node R240: Stale (last: Warning)</span>`, `<p class="hero-s worst">`,
		"<span>2 stale</span>", "<span>1 OK</span>", `<span class="dataage">Data as of`, `id="attn-h">Also needs attention`).
		lacks(t, "hero-incident", "num-xl")
	body := r.rec.Body.String()
	if strings.Index(body, `class="hero-s worst"`) > strings.Index(body, `id="fleet-h"`) {
		t.Fatal("the worst item must come before the fleet")
	}
}

// TestIncidentModeOnlyWhileCritical: B's incident mode (display numeral, glow class) is
// on while a server is critical, and off otherwise.
func TestIncidentModeOnlyWhileCritical(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t)
	now := h.clock.Now()
	h.fleet.servers = []ServerView{
		hostAt(now, "a", "Node A", nil, bmc.PowerOn, time.Time{}),
		hostAt(now, "gw", "Gateway", []string{"critical"}, bmc.PowerOff, time.Time{}),
	}
	result(c.get("/")).contains(t, `class="hero hero-crit hero-incident"`, `<span class="num-xl">1</span> critical`,
		`<span class="hero-t verdict">Gateway: `)
	h.fleet.servers = h.fleet.servers[:1]
	result(c.get("/")).contains(t, `class="hero hero-ok"`, "All 1 servers healthy").lacks(t, "hero-incident", "num-xl")
}

func TestHeroTitleAndCounts(t *testing.T) {
	t.Parallel()
	v := overviewView{Counts: fleetCounts{Total: 2, OK: 2}, Attention: []attentionItem{{Server: "a", Text: "x"}},
		Servers: []summaryRow{{Name: "a", Health: healthView{Class: "ok"}}}}
	if h := heroOf(v); h.Title != "Warning or critical events in the last 24 h" || h.Tone != "warn" || h.Worst == nil {
		t.Errorf("events only: %+v", h)
	}
	m := overviewView{Counts: fleetCounts{Total: 2, Maintenance: 2}}
	if h := heroOf(m); h.Title != "All 2 servers in maintenance" || h.Tone != "maint" {
		t.Errorf("all in maintenance: %+v", h)
	}
	healthy := overviewView{Healthy: true, Counts: fleetCounts{Total: 3, OK: 2, Maintenance: 1}}
	if h := heroOf(healthy); h.Title != "All other servers healthy" || strings.Join(h.Counts, ",") != "1 in maintenance,2 OK" {
		t.Errorf("healthy with maintenance: %+v", h)
	}
	if got := heroTitle(overviewView{Counts: fleetCounts{Total: 1, Unknown: 1}}); got != "1 unknown" {
		t.Errorf("fallback title %q", got)
	}
}

// TestOverviewRecorder: with the sensor history wired, the desktop fleet view is a row
// per server on one 24 h axis, each with a text summary and a data table; a server
// without history says so. Without history only the compact list is drawn.
func TestOverviewRecorder(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t, withHistory(t))
	r := result(c.get("/")).status(t, http.StatusOK)
	r.contains(t, `<div class="rec only-wide">`, `class="rec-svg" viewBox="0 0 720 40" preserveAspectRatio="none" aria-hidden="true"`,
		`class="rec-tick t`, `class="rec-now">now</span>`, "Data table: fleet, last 24 hours", `aria-label="Fleet history table"`,
		"Storage node R730XD, ", ", last 24 hours: minimum ", "No history yet", `<ul class="clist only-narrow"`,
		`<h2 id="fleet-h">Fleet, last 24 hours</h2>`).lacks(t, "style=")
	row := between(between(r.rec.Body.String(), `class="rec-rows"`, "</ul>"), `href="/servers/r730xd"`, "</li>")
	if !strings.Contains(row, `class="rec-line" d="M`) || !strings.Contains(row, `class="rec-area" d="M`) {
		t.Fatalf("recorder row:\n%s", row)
	}
	_, plain := signedIn(t)
	result(plain.get("/")).contains(t, `<ul class="clist" aria-label="Servers, worst first">`, `<h2 id="fleet-h">Fleet</h2>`).
		lacks(t, `class="rec only-wide"`)
}

func TestWithoutReadings(t *testing.T) {
	t.Parallel()
	p := history.SparkPlan(time.Date(2026, 10, 23, 12, 10, 0, 0, time.UTC))
	for have, want := range map[int]string{48: "No gaps", 47: "30 min without readings", 43: "2 h 30 min without readings",
		46: "1 h without readings"} {
		if got := withoutReadings(p, have); got != want {
			t.Errorf("%d buckets: %q, want %q", have, got, want)
		}
	}
}

// TestHeroNamesTheServerOfThePillsWorstState (review L5): the title follows the same
// classification as the counts, the tone and incident mode, whatever the row order.
func TestHeroNamesTheServerOfThePillsWorstState(t *testing.T) {
	t.Parallel()
	stale := summaryRow{Name: "Old", Health: healthView{Label: "Stale (last: Critical)", Class: "stale"}, Fresh: freshness{Stale: true}}
	crit := summaryRow{Name: "Gate", Health: healthView{Label: "Critical", Class: "crit"}}
	rows := []summaryRow{stale, crit}
	v := overviewView{Servers: rows, Counts: countFleet(rows), Attention: []attentionItem{{Server: "Old"}}}
	h := heroOf(v)
	if h.Title != "Gate: Critical" || h.Tone != "crit" || !h.Incident {
		t.Fatalf("hero %+v", h)
	}
	only := []summaryRow{stale}
	h = heroOf(overviewView{Servers: only, Counts: countFleet(only), Attention: []attentionItem{{Server: "Old"}}})
	if h.Title != "Old: Stale (last: Critical)" || h.Tone != "stale" || h.Incident {
		t.Fatalf("stale hero %+v", h)
	}
}

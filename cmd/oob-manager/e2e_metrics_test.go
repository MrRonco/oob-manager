//go:build e2e

package main

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

const e2eMetricsYAML = "metrics: { enabled: true, allow_networks: [127.0.0.1/32] }\n"

// checkMetrics scrapes /metrics through the real stack: a read-only token works, no
// token and a signed-in admin's session cookie do not, the scrape carries the cached
// sensor data without identifiers, and scrapes add no BMC request.
func checkMetrics(t *testing.T) {
	s := startStackWith(t, "127.0.0.1:0", e2eMetricsYAML)
	b := browser{t: t, base: s.base, c: s.client(t)}
	if p := b.get("/metrics"); p.status != http.StatusUnauthorized {
		t.Fatalf("no token: %d", p.status)
	}
	login(t, b, s) // an admin session cookie is now in b's jar
	if p := b.get("/metrics"); p.status != http.StatusUnauthorized {
		t.Fatalf("admin session cookie accepted: %d", p.status)
	}
	p := scrape(t, b, s)
	if p.status != http.StatusOK || !strings.HasPrefix(p.header.Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("scrape: %d %q", p.status, p.header.Get("Content-Type"))
	}
	expectPage(t, p, `oob_server_up{server="r730xd"} 1`, `oob_server_up{server="r240"} 1`,
		`oob_temperature_celsius{server="r730xd",`, `oob_fan_speed_rpm{server="r730xd",`,
		`oob_server_health{server="r240",state=`, `oob_login_failures_total{stage="password"}`,
		`oob_audit_chain_ok 1`, "oob_build_info{")
	if strings.Contains(p.body, "serial=") || strings.Contains(p.body, "service_tag=") {
		t.Fatal("identifiers exposed without metrics.include_inventory")
	}
	if p = b.do(http.MethodPost, "/metrics", s.token, nil); p.status != http.StatusMethodNotAllowed {
		t.Fatalf("POST /metrics: %d", p.status)
	}
	checkMetricsMaintenance(t, b, s)
	assertScrapesSilent(t, b, s)
}

// checkMetricsMaintenance: a window started in the UI shows in the next scrape with its
// end time, and the server still reports its real health (tech_doc §30).
func checkMetricsMaintenance(t *testing.T, b browser, s *stack) {
	t.Helper()
	expectRedirect(t, b.submit("/servers/r240/maintenance/new", "/servers/r240/maintenance",
		url.Values{"reason": {"metrics check"}, "duration": {"1h"}}), "/servers/r240/activity#maint")
	var p page
	waitFor(t, "maintenance in the scrape", func() bool { // the render is reused for 1 s
		p = scrape(t, b, s)
		return strings.Contains(p.body, `oob_server_maintenance{server="r240"} 1`)
	})
	expectPage(t, p, `oob_server_maintenance{server="r730xd"} 0`, `oob_server_maintenance_until_timestamp_seconds{server="r240"} 1.`,
		`oob_server_maintenance_until_timestamp_seconds{server="r730xd"} 0`, `oob_server_health{server="r240",state=`)
	if strings.Contains(p.body, `oob_server_health{server="r240",state="unknown"} 1`) {
		t.Fatal("a server in maintenance hides its health")
	}
	expectRedirect(t, b.submit("/servers/r240/activity", "/servers/r240/maintenance/end", nil), "/servers/r240/activity#maint")
}

// assertScrapesSilent: a burst of scrapes adds no request to any mock BMC. The poller
// keeps running in the background, so a burst that overlaps a poll is retried.
func assertScrapesSilent(t *testing.T, b browser, s *stack) {
	t.Helper()
	count := func() int {
		n := 0
		for _, m := range s.mocks {
			n += len(m.Requests())
		}
		return n
	}
	for range 3 {
		before := count()
		for range 10 {
			if p := scrape(t, b, s); p.status != http.StatusOK {
				t.Fatalf("scrape: %d", p.status)
			}
		}
		if count() == before {
			return
		}
	}
	t.Fatal("every scrape burst coincided with BMC requests")
}

// scrape fetches /metrics with the shared read-only token. Every subtest spends from
// that token's 60-per-minute budget, so a 429 here means an earlier subtest used it up,
// not a fault: the scrape waits as long as Retry-After says (at most 65 s in all).
func scrape(t *testing.T, b browser, s *stack) page {
	t.Helper()
	deadline := time.Now().Add(65 * time.Second)
	for {
		p := b.do(http.MethodGet, "/metrics", s.token, nil)
		if p.status != http.StatusTooManyRequests {
			return p
		}
		wait, err := strconv.Atoi(p.header.Get("Retry-After"))
		if err != nil || wait < 1 || time.Now().Add(time.Duration(wait)*time.Second).After(deadline) {
			t.Fatalf("scrape: 429 with Retry-After %q", p.header.Get("Retry-After"))
		}
		time.Sleep(time.Duration(wait) * time.Second)
	}
}

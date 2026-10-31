//go:build e2e

package main

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var (
	e2eRevRE     = regexp.MustCompile(`name="rev" value="(\d+)"`)
	e2eEastern   = regexp.MustCompile(`<a class="clock-link"[^>]*><time datetime="[^"]+Z">\d\d:\d\d:\d\d E[DS]T</time>`)
	e2eTokyo     = regexp.MustCompile(`<a class="clock-link"[^>]*><time datetime="[^"]+Z">\d\d:\d\d:\d\d JST</time>`)
	e2eUTCClock  = regexp.MustCompile(`<a class="clock-link"[^>]*><time datetime="[^"]+Z">\d\d:\d\d:\d\d UTC</time>`)
	e2eLockedRow = regexp.MustCompile(`(?s)name="ratelimit\.login_acct_per_hour" type="text"[^>]*disabled`)
)

// checkGeneral drives slice S2 through the real stack: the app-wide display time zone
// changed in Settings → General (live, audited), an invalid zone and a file-managed
// key refused, and a viewer's own time zone overriding the default for them only.
func checkGeneral(t *testing.T, b browser, s *stack) {
	if !e2eUTCClock.MatchString(b.get("/").body) {
		t.Fatal("top bar clock not in UTC before any change")
	}
	gen := b.get("/settings/general")
	expectPage(t, gen, "Managed by config.yaml", "Set in config.yaml (ratelimit.login_acct_per_hour)")
	if !e2eLockedRow.MatchString(gen.body) {
		t.Fatal("file-managed key is editable")
	}
	rev := e2eRevRE.FindStringSubmatch(gen.body)
	if rev == nil {
		t.Fatal("no rev on the form")
	}
	bad := b.submit("/settings/general", "/settings/general", url.Values{"rev": {rev[1]}, "ui.time_zone": {"US/Eastern"}})
	if bad.status != http.StatusUnprocessableEntity || !strings.Contains(bad.body, "ui.time_zone") {
		t.Fatalf("invalid zone: %d", bad.status)
	}
	locked := b.submit("/settings/general", "/settings/general", url.Values{"rev": {rev[1]}, "ratelimit.login_acct_per_hour": {"15"}})
	if locked.status != http.StatusForbidden {
		t.Fatalf("file-managed key accepted: %d", locked.status)
	}
	expectRedirect(t, b.submit("/settings/general", "/settings/general",
		url.Values{"rev": {rev[1]}, "ui.time_zone": {"America/New_York"}}), "/settings/general?done=general")
	if !e2eEastern.MatchString(b.get("/").body) {
		t.Fatal("app default time zone not applied to the top bar clock")
	}

	viewer := browser{t: t, base: s.base, c: s.viewer}
	if !e2eEastern.MatchString(viewer.get("/").body) {
		t.Fatal("viewer does not get the app default")
	}
	expectRedirect(t, viewer.submit("/preferences", "/preferences", url.Values{"time_zone": {"Asia/Tokyo"},
		"theme": {"nord"}, "date_format": {"iso"}, "clock": {"24h"}, "temp_unit": {"c"}, "density": {"compact"}}),
		"/preferences?done=saved")
	mine := viewer.get("/")
	if !e2eTokyo.MatchString(mine.body) || !strings.Contains(mine.body, `data-palette="nord"`) {
		t.Fatal("viewer's own time zone and theme not applied")
	}
	if !e2eEastern.MatchString(b.get("/").body) {
		t.Fatal("a user's preference changed the admin's view")
	}
	if p := viewer.get("/settings/general"); p.status != http.StatusForbidden {
		t.Fatalf("viewer reached General: %d", p.status)
	}
	// Leave the default as found for the later checks (they match UTC-free text only).
	cur := e2eRevRE.FindStringSubmatch(b.get("/settings/general").body)
	expectRedirect(t, b.submit("/settings/general", "/settings/general",
		url.Values{"rev": {cur[1]}, "ui.time_zone": {"UTC"}}), "/settings/general?done=general")
}

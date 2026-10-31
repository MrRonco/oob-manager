package ui

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/store"
)

// TestActivityShowsActionsOnlyToEveryRole (plan 04 §11 item 8): the Activity pages show
// what was done to the servers to every role, and never addresses, sign-ins, step-ups,
// token or settings changes, or refusals.
func TestActivityShowsActionsOnlyToEveryRole(t *testing.T) {
	e := newMaintEnv(t)
	ctx := context.Background()
	const ip = "203.0.113.77"
	for _, en := range []audit.Entry{
		{Principal: "alice", Action: "auth.login", Result: audit.ResultOK},
		{Principal: "alice", Action: "auth.stepup", Result: audit.ResultOK},
		{Principal: "alice", Action: "admin.general.update", Result: audit.ResultOK, Params: map[string]any{"poll": "secret-setting"}},
		{Principal: "alice", Action: "token.create", Result: audit.ResultOK},
		{Principal: "alice", ServerID: "r730xd", Action: string(authz.PowerGracefulRestart), Result: audit.ResultStarted,
			Params: map[string]any{"note": "private-param"}},
		{Principal: "alice", ServerID: "r730xd", Action: string(authz.PowerGracefulRestart), Result: audit.ResultOK},
		{Principal: "dave", ServerID: "r730xd", Action: string(authz.PowerForceOff), Result: audit.ResultError},
		{Principal: "bob", ServerID: "r240", Action: string(authz.PowerForceOff), Result: audit.ResultDenied},
		{Principal: "carol", ServerID: "r240", Action: string(authz.FanLeaseCreate), Result: audit.ResultOK},
		{Principal: "system", ServerID: "r730xd", Action: "bmc.reset.verified", Result: audit.ResultError},
	} {
		en.SrcIP = ip
		if _, err := e.deps.Audit.Record(ctx, en); err != nil {
			t.Fatal(err)
		}
	}
	viewer := e.userClient(t, "vera", authz.RoleViewer, "192.0.2.31")
	page := result(viewer.get("/activity")).status(t, http.StatusOK)
	page.contains(t, "<h1>Activity</h1>", `href="/activity" aria-current="page">`, "<strong>alice</strong> asked for a graceful restart on",
		`href="/servers/r730xd">Storage node R730XD</a>`, "<strong>carol</strong> started a fan lease",
		"BMC did not answer in time after its restart", "<strong>dave</strong> forced the power off", "Failed").
		lacks(t, ip, "signed in", "secret-setting", "private-param", "API token", "token.create", "general settings", "bob", "auth.",
			"step-up", "Sign-in refused")
	if n := strings.Count(page.rec.Body.String(), "asked for a graceful restart"); n != 1 {
		t.Fatalf("a power action is shown once (requested), not again for its final row: %d", n)
	}
	srv := result(viewer.get("/servers/r240/activity")).status(t, http.StatusOK)
	srv.contains(t, "<strong>carol</strong> started a fan lease", `id="act-h">Actions on this server`).
		lacks(t, "alice", ip, "bob", " on <a href")
	if strings.Contains(srv.rec.Body.String(), "graceful restart") {
		t.Fatal("another server's action is on this server's Activity tab")
	}
}

func TestActivityRowsAndPaging(t *testing.T) {
	names := map[string]string{"a": "Node A"}
	tf := fmtIn(nil)
	for _, rec := range []store.AuditRecord{{Action: "auth.login", Result: "ok"}, {Action: "power.on", Result: "denied"},
		{Action: "power.on", Result: "ok"}, {Action: "server.maintenance.start", Result: "started"}} {
		if _, ok := activityRowOf(rec, names, tf); ok {
			t.Errorf("%+v must not be shown", rec)
		}
	}
	row, ok := activityRowOf(store.AuditRecord{Action: "server.maintenance.end", Result: "ok", ServerID: "gone", Principal: "x"}, names, tf)
	if !ok || row.ServerName != "gone" || row.Text != "ended maintenance" || row.Result.Class != "ok" {
		t.Fatalf("row %+v", row)
	}
	for _, m := range activityMatches() {
		if txt, ok := activityText(m.Action, m.Result); !ok || txt == "" {
			t.Errorf("pair %+v has no sentence", m)
		}
	}
	if n := len(activityMatches()); n > store.MaxAuditFilterMatches {
		t.Errorf("%d pairs exceed the store's bound", n)
	}
	for in, want := range map[string]bool{"": true, "12": true, "0": false, "-3": false, "x": false} {
		if _, ok := parseBefore(in); ok != want {
			t.Errorf("parseBefore(%q) ok = %v", in, ok)
		}
	}
	_, c := signedIn(t) // no audit log wired
	result(c.get("/activity")).status(t, http.StatusOK).contains(t, "not available in this installation")
	result(c.get("/activity?before=x")).status(t, http.StatusBadRequest)
	result(c.get("/servers/r730xd/activity?before=x")).status(t, http.StatusBadRequest)
}

func TestPillShowsTheShortWorstWord(t *testing.T) {
	for in, want := range map[string]string{
		"1 critical · 1 stale": "1 critical", "2 OK · 1 off": "1 off", "2 stale · 1 in maintenance": "2 stale",
		"1 OK · 1 in maintenance": "1 maint.", "1 warning": "",
	} {
		if got := (pillView{Text: in}).short().Short; got != want {
			t.Errorf("short(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestServerTabsAndSidebar (plan 04 §11 item 8): the stable tab set, Activity in the
// sidebar, About only in the account menu and the footer.
func TestServerTabsAndSidebar(t *testing.T) {
	_, c := signedIn(t, withHistory(t))
	body := result(c.get("/servers/r730xd/sensors")).status(t, http.StatusOK).rec.Body.String()
	tabs := between(body, `aria-label="Server sections"`, "</nav>")
	last := -1
	for _, name := range []string{"Overview", "Sensors", "History", "Events", "Activity", "Inventory"} {
		i := strings.Index(tabs, "<span>"+name+"</span>")
		if i < last {
			t.Fatalf("tab %s missing or out of order:\n%s", name, tabs)
		}
		last = i
	}
	if strings.Contains(tabs, "Operations") || strings.Contains(tabs, "Console") || strings.Contains(tabs, "Hardware") {
		t.Fatalf("retired tabs:\n%s", tabs)
	}
	side := between(body, `<aside class="side"`, "</aside>")
	if !strings.Contains(side, `href="/activity"`) || strings.Contains(side, `href="/about"`) {
		t.Fatalf("sidebar:\n%s", side)
	}
}

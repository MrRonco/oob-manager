package ui

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
	"oob-manager/internal/firmware"
	"oob-manager/internal/fleet"
	"oob-manager/internal/fwcatalog"
	"oob-manager/internal/fwinventory"
	"oob-manager/internal/store"
)

// fakeFirmware is the firmware view as the UI sees it.
type fakeFirmware struct {
	mu        sync.Mutex
	rows      []firmware.Row
	scans     []fwinventory.ServerScan
	changes   []store.FirmwareChangeRow
	filters   []firmware.Filter
	rescans   []string
	rescanErr error
	warnCalls int
	catalog   fwcatalog.Status
}

func (f *fakeFirmware) Table(_ context.Context, flt firmware.Filter) fwinventory.Table {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.filters = append(f.filters, flt)
	t := fwinventory.Table{Total: len(f.rows), Servers: f.scans, Catalog: f.catalog}
	for _, r := range f.rows {
		if r.Primary().Warn() {
			t.Warn++
		}
		if r.Update.Newer() {
			t.Updates++
			if r.Update.State == firmware.UpdateUrgent {
				t.Urgent++
			}
		}
		if r.Primary().Flagged() {
			t.Flagged++
		}
		if flt.Match(r) {
			t.Rows = append(t.Rows, r)
		}
	}
	firmware.SortRows(t.Rows)
	return t
}

func (f *fakeFirmware) Server(_ context.Context, id string) (fwinventory.ServerView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, sc := range f.scans {
		if sc.Info.ID != id {
			continue
		}
		v := fwinventory.ServerView{ServerScan: sc, Changes: f.changes}
		for _, r := range f.rows {
			if r.Server.ID == id {
				v.Rows = append(v.Rows, r)
			}
		}
		return v, nil
	}
	return fwinventory.ServerView{}, fwinventory.ErrNotFound
}

func (f *fakeFirmware) WarnCount(ctx context.Context) int {
	f.mu.Lock()
	f.warnCalls++
	f.mu.Unlock()
	return f.Table(ctx, firmware.Filter{}).Warn
}

func (f *fakeFirmware) Rescan(_ context.Context, a admin.Actor, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rescanErr != nil {
		return f.rescanErr
	}
	f.rescans = append(f.rescans, a.Username+"/"+id)
	return nil
}

var fwNow = time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)

func newFakeFirmware() *fakeFirmware {
	r730 := firmware.ServerInfo{ID: "r730xd", Name: "Storage node R730XD", BMCKind: "idrac8"}
	r240 := firmware.ServerInfo{ID: "r240", Name: "Edge node R240", BMCKind: "idrac9"}
	return &fakeFirmware{
		rows: []firmware.Row{
			{Server: r730, Component: firmware.Component{Key: firmware.Key{ComponentID: "159"}, Kind: bmc.FirmwareBIOS, Name: "BIOS",
				Named: true, Running: "2.19.0", Previous: "2.18.1"},
				Verdict: firmware.Verdict{Flags: []firmware.Flag{firmware.FlagBelowMinimum}, Minimum: "2.20.0", Note: "BIOS fix"}, Display: "BIOS"},
			{Server: r730, Component: firmware.Component{Key: firmware.Key{ComponentID: "101434"}, Kind: bmc.FirmwareEnclosure,
				Name: "Backplane 0", Named: true, Running: "2.23", Stored: "2.25"},
				Verdict: firmware.Verdict{Flags: []firmware.Flag{firmware.FlagNotApplied}}, Display: "Backplane 0"},
			{Server: r730, Component: firmware.Component{Key: firmware.Key{ComponentID: "106802"}, Kind: bmc.FirmwareOther,
				Name: "Component 106802", Running: "RS03", Staged: "RS04"}, Display: "Unnamed component (ID 106802)"},
			{Server: r240, Component: firmware.Component{Key: firmware.Key{ComponentID: "105897", FQDD: "NIC.Embedded.1-1-1"},
				Kind: bmc.FirmwareNIC, Name: "<b>Broadcom</b>", Named: true, Running: "23.31.1",
				ReleaseDate: time.Date(2025, 9, 27, 0, 0, 0, 0, time.UTC)}, Display: "<b>Broadcom</b>"},
		},
		scans: []fwinventory.ServerScan{
			{Info: r730, Scanned: true, Scan: store.FirmwareScanRow{ScannedAt: fwNow.Add(-time.Hour), Listed: 70, Components: 3},
				Status: fwinventory.ScanStatus{Enabled: true, Next: fwNow.Add(23 * time.Hour)}},
			{Info: r240, Status: fwinventory.ScanStatus{Enabled: true, Requested: true, Error: "timeout"}},
		},
		changes: []store.FirmwareChangeRow{{Name: "BIOS", ComponentID: "159", Field: "running", Before: "2.18.1", After: "2.19.0",
			SeenAt: fwNow.Add(-time.Hour)}},
	}
}

type fwEnv struct {
	*settingsEnv
	fw *fakeFirmware
}

func newFWEnv(t *testing.T) *fwEnv {
	t.Helper()
	fw := newFakeFirmware()
	e := newSettingsEnv(t, func(d *Deps) { d.Firmware = fw })
	return &fwEnv{settingsEnv: e, fw: fw}
}

func (e *fwEnv) userClient(t *testing.T, name string, role authz.Role, ip string) *client {
	t.Helper()
	link, err := e.svc.CreateUser(context.Background(), actorFor(t, e.settingsEnv, "morgan"), name, role)
	must(t, err)
	c := e.client(ip)
	c.login(name, e.enrolViaLink(link.Token, testPassword))
	return c
}

func TestFirmwarePageViewer(t *testing.T) {
	t.Parallel()
	e := newFWEnv(t)
	viewer := e.userClient(t, "vera", authz.RoleViewer, "192.0.2.31")
	page := result(viewer.get("/firmware")).status(t, http.StatusOK)
	page.contains(t, "<h1>Firmware</h1>", `href="/firmware" aria-current="page"`, `<span class="cnt">1</span>`,
		"Below minimum", "Not applied", `<span class="nw">minimum 2.20.0</span> · BIOS fix`, "(2.25 stored on the BMC, not installed)",
		`<span class="nodata">Unnamed component (ID 106802)</span>`, "RS04", "2025-09", "&lt;b&gt;Broadcom&lt;/b&gt;",
		"4 components", `href="/firmware?flagged=1"><svg class="ic ic-triangle-alert"`, `<use href="#i-triangle-alert"/></svg> 2 flagged</a>`, `href="/firmware.csv?"`, "Running is the version the device runs",
		"Scanning…", "The last scan failed (timed out)", "64 of 70 firmware entries were read", "No vendor catalog is imported, so firmware updates are not checked.",
		`<option value="bios">BIOS</option>`, `<option value="r240">Edge node R240</option>`).
		lacks(t, "<b>Broadcom</b>", "Re-scan firmware", "Component ID</th>", "Lifecycle inventory", "Mismatch")
	body := page.rec.Body.String()
	if strings.Index(body, "BIOS</th>") > strings.Index(body, "Backplane 0</th>") ||
		strings.Index(body, "Backplane 0</th>") > strings.Index(body, "Broadcom") {
		t.Fatal("problems first")
	}
	result(viewer.get("/firmware?details=1")).status(t, http.StatusOK).contains(t, "Component ID</th>", "NIC.Embedded.1-1-1",
		"Hide component IDs")
	result(viewer.get("/firmware?flagged=1&kind=bios&server=r730xd&q=2.19")).status(t, http.StatusOK).
		contains(t, "1 shown", `<option value="bios" selected>`, "Clear filters", `href="/firmware.csv?flagged=1&amp;kind=bios&amp;q=2.19&amp;server=r730xd"`).
		lacks(t, "Backplane 0</th>")
	result(viewer.get("/firmware?kind=cpu")).status(t, http.StatusBadRequest)
	result(viewer.get("/firmware?q=zzz")).status(t, http.StatusOK).contains(t, "No component matches these filters.")
	for _, p := range []string{"/firmware", "/firmware?details=1", "/servers/r730xd/inventory"} {
		b := appScript.ReplaceAllString(viewer.get(p).Body.String(), "")
		if containsAny(b, "<script", " style=", "javascript:", " on"+"click=") {
			t.Errorf("%s is not CSP clean", p)
		}
	}
	// The sidebar entry is on every page.
	result(viewer.get("/")).contains(t, `href="/firmware"`, `<span class="cnt">2</span>`)
}

func TestFirmwareRescanOperator(t *testing.T) {
	t.Parallel()
	e := newFWEnv(t)
	op := e.userClient(t, "oscar", authz.RoleOperator, "192.0.2.30")
	page := result(op.get("/firmware")).status(t, http.StatusOK)
	page.contains(t, `action="/servers/r730xd/firmware/rescan"`, `name="from" value="firmware"`,
		"Re-scan: a scan is already waiting or running.").lacks(t, `action="/servers/r240/firmware/rescan"`)
	rec := op.submit("/firmware", "/servers/r730xd/firmware/rescan", formOf("from", "firmware"))
	result(rec).status(t, http.StatusSeeOther).location(t, "/firmware?done=rescan")
	result(op.get("/firmware?done=rescan")).contains(t, "Re-scan requested.")
	rec = op.submit("/servers/r730xd/inventory", "/servers/r730xd/firmware/rescan", nil)
	result(rec).status(t, http.StatusSeeOther).location(t, "/servers/r730xd/inventory?done=rescan#fw-h")
	if len(e.fw.rescans) != 2 || e.fw.rescans[0] != "oscar/r730xd" {
		t.Fatalf("rescans %v", e.fw.rescans)
	}
	e.fw.rescanErr = fleet.ErrPaused
	result(op.submit("/firmware", "/servers/r730xd/firmware/rescan", formOf("from", "firmware"))).status(t, http.StatusConflict).
		contains(t, "Polling of this server is paused")
	e.fw.rescanErr = fwinventory.ErrUnavailable
	result(op.submit("/firmware", "/servers/r730xd/firmware/rescan", formOf("from", "firmware"))).status(t, http.StatusNotFound)
	e.fw.rescanErr = context.DeadlineExceeded
	result(op.submit("/firmware", "/servers/r730xd/firmware/rescan", formOf("from", "firmware"))).status(t, http.StatusInternalServerError).
		lacks(t, "deadline")
	e.fw.rescanErr = nil
	// Six re-scans a minute per user (five so far), then 429 (with Retry-After) and an
	// audited refusal.
	result(op.submit("/firmware", "/servers/r730xd/firmware/rescan", formOf("from", "firmware"))).status(t, http.StatusSeeOther)
	rec = op.submit("/firmware", "/servers/r730xd/firmware/rescan", formOf("from", "firmware"))
	result(rec).status(t, http.StatusTooManyRequests)
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("Retry-After missing")
	}
	if row, ok := e.findAudit(string(authz.FirmwareRescan), audit.ResultDenied); !ok || row.ErrorClass != "rate_limited" {
		t.Fatalf("rate limit not audited: %+v", row)
	}
}

func TestFirmwareRescanRefusals(t *testing.T) {
	t.Parallel()
	e := newFWEnv(t)
	viewer := e.userClient(t, "vera", authz.RoleViewer, "192.0.2.31")
	op := e.userClient(t, "oscar", authz.RoleOperator, "192.0.2.30")
	token := csrfForAny(t, op.get("/firmware").Body.String(), "/servers/r730xd/firmware/rescan")
	// A viewer with a valid form token of their own session: refused by role and audited.
	vtoken := e.csrfToken(viewer)
	result(viewer.do(http.MethodPost, "/servers/r730xd/firmware/rescan", formOf(csrfField, vtoken))).status(t, http.StatusForbidden)
	if row, ok := e.findAudit(string(authz.FirmwareRescan), audit.ResultDenied); !ok || row.ErrorClass != "forbidden" ||
		row.ServerID != "r730xd" {
		t.Fatalf("viewer refusal %+v", row)
	}
	result(op.do(http.MethodPost, "/servers/r730xd/firmware/rescan", formOf(csrfField, "bogus"))).status(t, http.StatusForbidden)
	result(op.do(http.MethodPost, "/servers/nope/firmware/rescan", formOf(csrfField, token))).status(t, http.StatusNotFound)
	result(op.do(http.MethodPost, "/servers/..%2f/firmware/rescan", formOf(csrfField, token))).status(t, http.StatusNotFound)
	if len(e.fw.rescans) != 0 {
		t.Fatalf("refused re-scans reached the service: %v", e.fw.rescans)
	}
}

func TestFirmwareCSVFromTheUI(t *testing.T) {
	t.Parallel()
	e := newFWEnv(t)
	viewer := e.userClient(t, "vera", authz.RoleViewer, "192.0.2.31")
	rec := viewer.get("/firmware.csv?server=r730xd")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/csv; charset=utf-8" ||
		!strings.HasPrefix(rec.Header().Get("Content-Disposition"), `attachment; filename="firmware_r730xd_`) {
		t.Fatalf("csv %d %v", rec.Code, rec.Header())
	}
	recs, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil || len(recs) != 4 || recs[0][0] != "server_id" || recs[1][5] != "159" {
		t.Fatalf("records %q %v", recs, err)
	}
	result(viewer.get("/firmware.csv?kind=cpu")).status(t, http.StatusBadRequest)
	for range 5 { // six exports a minute per user (the bad filter above was refused before the limit)
		result(viewer.get("/firmware.csv")).status(t, http.StatusOK)
	}
	result(viewer.get("/firmware.csv")).status(t, http.StatusTooManyRequests)
}

func TestInventoryFirmwareSection(t *testing.T) {
	t.Parallel()
	e := newFWEnv(t)
	op := e.userClient(t, "oscar", authz.RoleOperator, "192.0.2.30")
	page := result(op.get("/servers/r730xd/inventory")).status(t, http.StatusOK)
	page.contains(t, `<h2 id="fw-h">Firmware</h2>`, `<th scope="rowgroup" colspan="9">BIOS</th>`,
		`<th scope="rowgroup" colspan="9">Backplane or enclosure</th>`, "Last scan 08:00 · next in 23 h",
		`action="/servers/r730xd/firmware/rescan"`, `name="from" value="inventory"`, "Recent changes",
		"BIOS: running <span class=\"mono\">2.18.1</span> → <span class=\"mono\">2.19.0</span>",
		"Show component IDs and FQDDs", `href="/firmware"`).
		lacks(t, "Installed is what runs now", "Component ID</th>")
	result(op.get("/servers/r730xd/inventory?details=1")).contains(t, "Component ID</th>", "Hide component IDs")
	result(op.get("/servers/r730xd/inventory?done=rescan")).contains(t, "Re-scan requested.")
	result(op.get("/servers/r240/inventory")).status(t, http.StatusOK).contains(t, "Scanning…", "Re-scan: a scan is already waiting")
	// A server the view does not know (never scanned, not polled by the fake): no section.
	result(op.get("/servers/spare/inventory")).status(t, http.StatusOK).lacks(t, `<h2 id="fw-h">`)
}

func TestFirmwareHiddenWithoutService(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t)
	result(c.get("/firmware")).status(t, http.StatusNotFound)
	result(c.get("/firmware.csv")).status(t, http.StatusNotFound)
	result(c.get("/")).lacks(t, `href="/firmware"`)
	// The Inventory tab keeps the poller's firmware list, with the new legend.
	result(c.get("/servers/r730xd/inventory")).contains(t, "Running is what the device reports it runs (Dell: Installed)",
		"Integrated Dell Remote Access Controller")
}

func TestFirmwareHelpersAndFlags(t *testing.T) {
	t.Parallel()
	now := fwNow
	for _, c := range []struct {
		next time.Time
		want string
	}{{now.Add(30 * time.Second), "now"}, {now.Add(40 * time.Minute), "in 40 min"}, {now.Add(23*time.Hour + 40*time.Minute), "in 24 h"}} {
		if got := untilText(c.next, now); got != c.want {
			t.Errorf("untilText = %q, want %q", got, c.want)
		}
	}
	for f, class := range map[firmware.Flag]string{firmware.FlagBelowMinimum: "warn", firmware.FlagNotApplied: "info",
		firmware.FlagCannotCompare: "info", firmware.FlagStale: "info", firmware.FlagOK: "ok"} {
		if got := flagView(f); got.Class != class || got.Label != f.Label() {
			t.Errorf("flag %s = %+v", f, got)
		}
	}
	ok := firmware.Row{Verdict: firmware.Verdict{Minimum: "1.0"}, Component: firmware.Component{Running: "1.0"}}
	if v := fwRow(ok, now); len(v.Flags) != 1 || v.Flags[0].Label != "OK" {
		t.Fatalf("a met minimum shows OK: %+v", v)
	}
}

func formOf(kv ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

// TestFirmwareReviewFixes covers the UI items of the 2026-10-23 review: the per-server
// re-scan cooldown answers 429 (S-M4), a paused server offers no Re-scan (C-L9), the kind
// separators are row groups and no empty <strong> is rendered (C-L9), the minimum alone
// does not wrap but a long note does (C-M3), and the sidebar count comes from WarnCount
// (S-L4).
func TestFirmwareReviewFixes(t *testing.T) {
	t.Parallel()
	e := newFWEnv(t)
	op := e.userClient(t, "oscar", authz.RoleOperator, "192.0.2.30")
	e.fw.rescanErr = &fwinventory.CooldownError{Left: 20 * time.Second}
	rec := op.submit("/firmware", "/servers/r730xd/firmware/rescan", formOf("from", "firmware"))
	result(rec).status(t, http.StatusTooManyRequests).contains(t, "re-scanned moments ago")
	if rec.Header().Get("Retry-After") != "20" {
		t.Fatalf("Retry-After %q", rec.Header().Get("Retry-After"))
	}
	e.fw.rescanErr = nil

	e.fw.mu.Lock()
	e.fw.scans[0].Status.Paused = true
	e.fw.mu.Unlock()
	result(op.get("/firmware")).contains(t, "Polling is paused").lacks(t, `action="/servers/r730xd/firmware/rescan"`)

	inv := result(op.get("/servers/r730xd/inventory")).status(t, http.StatusOK)
	inv.contains(t, `<tbody>`, `<th scope="rowgroup" colspan="9">BIOS</th>`).lacks(t, `<strong></strong>`, `scope="colgroup"`)
	result(op.get("/firmware")).contains(t, `<span class="meta"><span class="nw">minimum 2.20.0</span> · BIOS fix</span>`).
		lacks(t, `<strong></strong>`)
	if e.fw.warnCalls == 0 {
		t.Fatal("the sidebar count does not use WarnCount")
	}
}

package ui

import (
	"context"
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
	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/fwcatalog"
	"oob-manager/internal/store"
)

// fakeUpdates records skip decisions.
type fakeUpdates struct {
	mu      sync.Mutex
	skips   []string
	unskips []string
	err     error
}

func (f *fakeUpdates) Skip(_ context.Context, a admin.Actor, r fwcatalog.SkipRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.skips = append(f.skips, a.Username+"/"+r.ServerID+"/"+r.ComponentID+"/"+r.FQDD+"/"+r.Version+"/"+r.Comment)
	return nil
}

func (f *fakeUpdates) Unskip(_ context.Context, a admin.Actor, server, component, fqdd string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unskips = append(f.unskips, a.Username+"/"+server+"/"+component+"/"+fqdd)
	return nil
}

type fwUpdEnv struct {
	*fwEnv
	upd *fakeUpdates
}

// newFWUpdEnv is the firmware view with a catalog in use: the R240's BIOS has a
// Recommended update, its iDRAC an Urgent one, and the R730XD's backplane a skipped one.
func newFWUpdEnv(t *testing.T) *fwUpdEnv {
	t.Helper()
	fw := newFakeFirmware()
	r240, r730 := fw.scans[1].Info, fw.scans[0].Info
	rel := func(v string, c catalog.Criticality, href string) catalog.Release {
		return catalog.Release{Version: v, Criticality: c, Date: time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC), Name: "Dell " + v,
			DetailsURL: href}
	}
	fw.rows = append(fw.rows,
		firmware.Row{Server: r240, Component: firmware.Component{Key: firmware.Key{ComponentID: "159", FQDD: "BIOS.Setup.1-1"},
			Kind: bmc.FirmwareBIOS, Name: "BIOS", Named: true, Running: "2.20.0"}, Display: "BIOS",
			Verdict: firmware.Verdict{Flags: []firmware.Flag{firmware.FlagUpdateAvailable}},
			Update: firmware.Update{State: firmware.UpdateAvailable, Candidates: 2, MatchedBy: "system_id",
				Latest: rel("2.25.2", catalog.CriticalityRecommended, "https://www.dell.com/support/x?driverId=1")}},
		firmware.Row{Server: r240, Component: firmware.Component{Key: firmware.Key{ComponentID: "25227", FQDD: "iDRAC.Embedded.1-1"},
			Kind: bmc.FirmwareBMC, Name: "iDRAC", Named: true, Running: "7.00.00.182", Stored: "7.00.00.185"}, Display: "iDRAC",
			Verdict: firmware.Verdict{Flags: []firmware.Flag{firmware.FlagUpdateUrgent}},
			Update: firmware.Update{State: firmware.UpdateUrgent, StoredIsLatest: true, Candidates: 1,
				Latest: rel("7.00.00.185", catalog.CriticalityUrgent, "javascript:alert(1)")}},
		firmware.Row{Server: r730, Component: firmware.Component{Key: firmware.Key{ComponentID: "27763"}, Kind: bmc.FirmwareOther,
			Name: "CPLD", Named: true, Running: "1.0.1"}, Display: "CPLD",
			Update: firmware.Update{State: firmware.UpdateSkipped, Latest: rel("1.0.6", catalog.CriticalityOptional, ""),
				Skip: &firmware.Skip{Version: "1.0.6", Comment: "<i>next window</i>", By: "morgan"}}},
	)
	fw.catalog = fwcatalog.Status{Source: "dell", Active: &store.CatalogImportRow{Version: "26.10.22", Signer: "FP",
		PublishedAt: time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC), ImportedAt: fwNow.Add(-3 * time.Hour)},
		LastCheck: &store.CatalogCheckRow{Result: "signature", At: fwNow.Add(-time.Hour)}}
	fw.scans[1].Coverage = firmware.Coverage{State: firmware.CoverageNormal, Components: 22, Matched: 9, Updates: 2, Urgent: 1}
	fw.scans[0].Coverage = firmware.Coverage{State: firmware.CoverageNotListed}
	upd := &fakeUpdates{}
	e := newSettingsEnv(t, func(d *Deps) { d.Firmware, d.FirmwareUpdates = fw, upd })
	return &fwUpdEnv{fwEnv: &fwEnv{settingsEnv: e, fw: fw}, upd: upd}
}

func TestFirmwarePageShowsUpdates(t *testing.T) {
	e := newFWUpdEnv(t)
	adm := e.adminClient()
	page := result(adm.get("/firmware")).status(t, http.StatusOK)
	page.contains(t, `<th scope="col">Latest</th>`, "Urgent update", "Update available", ">2.25.2<", "· Recommended",
		`href="https://www.dell.com/support/x?driverId=1"`, `rel="noopener noreferrer" target="_blank"`,
		"(already stored on the BMC: install it there)", "Skipped 1.0.6 by morgan: &lt;i&gt;next window&lt;/i&gt;",
		"Dell catalog 26.10.22 (published 2026-10-22)", "The last check failed (signature check",
		`<a class="chip" href="/firmware?updates=1">2 updates (1 urgent)</a>`, `id="fw-updates"`,
		"Update check: 9 of 22 components matched · 2 updates (1 urgent)",
		"Update check: The vendor catalog doesn&#39;t list this model",
		`action="/servers/r240/firmware/skip"`, `name="version" value="2.25.2"`, `action="/servers/r730xd/firmware/unskip"`)
	page.lacks(t, "javascript:", "<i>next window</i>")
	result(adm.get("/firmware?updates=1")).status(t, http.StatusOK).contains(t, ">2.25.2<", ">7.00.00.185<").
		lacks(t, ">RS03<", "Skipped 1.0.6")
	result(adm.get("/servers/r240/inventory")).status(t, http.StatusOK).contains(t, `<th scope="col">Latest</th>`,
		`action="/servers/r240/firmware/skip"`, `name="from" value="inventory"`)
	// An operator sees the updates but no skip control.
	op := e.userClient(t, "olga", authz.RoleOperator, "192.0.2.21")
	result(op.get("/firmware")).status(t, http.StatusOK).contains(t, ">2.25.2<").lacks(t, "/firmware/skip", "/firmware/unskip")
}

func TestSkipAndUnskipNeedAdminAndAFreshStepUp(t *testing.T) {
	e := newFWUpdEnv(t)
	adm := e.adminClient()
	form := url.Values{"component": {"159"}, "fqdd": {"BIOS.Setup.1-1"}, "version": {"2.25.2"}, "comment": {"next window"},
		"from": {"firmware"}}
	result(adm.submit("/firmware", "/servers/r240/firmware/skip", form)).status(t, http.StatusSeeOther).
		location(t, "/firmware?done=skipped")
	result(adm.submit("/servers/r730xd/inventory", "/servers/r730xd/firmware/unskip",
		url.Values{"component": {"27763"}, "fqdd": {""}})).status(t, http.StatusSeeOther).
		location(t, "/servers/r730xd/inventory?done=unskipped#fw-h")
	if len(e.upd.skips) != 1 || e.upd.skips[0] != "morgan/r240/159/BIOS.Setup.1-1/2.25.2/next window" ||
		len(e.upd.unskips) != 1 || e.upd.unskips[0] != "morgan/r730xd/27763/" {
		t.Fatalf("skips %v unskips %v", e.upd.skips, e.upd.unskips)
	}
	result(adm.get("/firmware?done=skipped")).contains(t, "Version skipped.")
	// A stale step-up keeps the form and asks again.
	e.clock.Advance(6 * time.Minute)
	resumeFrom(t, result(adm.submit("/firmware", "/servers/r240/firmware/skip", form)), "/firmware")
	if len(e.upd.skips) != 1 {
		t.Fatalf("skipped without a fresh step-up: %v", e.upd.skips)
	}
	if rec, ok := e.findAudit(string(authz.FirmwareSkipUpdate), audit.ResultDenied); !ok || rec.ErrorClass != "stepup_required" {
		t.Fatalf("refusal not audited: %+v %v", rec, ok)
	}
}

func TestSkipRefusesAChangedOrUnknownUpdate(t *testing.T) {
	e := newFWUpdEnv(t)
	adm := e.adminClient()
	cases := []struct {
		form url.Values
		code int
	}{
		{url.Values{"component": {"159"}, "fqdd": {"BIOS.Setup.1-1"}, "version": {"2.26.0"}, "comment": {"x"}}, http.StatusConflict},
		{url.Values{"component": {"999"}, "fqdd": {""}, "version": {"1"}, "comment": {"x"}}, http.StatusConflict},
		{url.Values{"component": {"bad id!"}, "fqdd": {""}, "version": {"1"}, "comment": {"x"}}, http.StatusBadRequest},
	}
	for _, c := range cases {
		result(adm.submit("/firmware", "/servers/r240/firmware/skip", c.form)).status(t, c.code)
	}
	e.upd.err = fwcatalog.ErrBadSkip
	result(adm.submit("/firmware", "/servers/r240/firmware/skip", url.Values{"component": {"159"}, "fqdd": {"BIOS.Setup.1-1"},
		"version": {"2.25.2"}, "comment": {strings.Repeat("x", 600)}})).status(t, http.StatusUnprocessableEntity)
	if len(e.upd.skips) != 0 {
		t.Fatalf("skipped %v", e.upd.skips)
	}
	op := e.userClient(t, "olga", authz.RoleOperator, "192.0.2.21")
	result(op.do(http.MethodPost, "/servers/r240/firmware/skip", url.Values{"component": {"159"}})).status(t, http.StatusForbidden)
}

func TestDetailsHrefAllowlist(t *testing.T) {
	for raw, want := range map[string]string{
		"https://www.dell.com/support/x?driverId=1": "https://www.dell.com/support/x?driverId=1",
		"https://dell.com/x":                        "https://dell.com/x",
		"http://www.dell.com/support":               "",
		"https://evil.example/dell.com":             "",
		"https://dell.com.evil.example/x":           "",
		"https://user@www.dell.com/x":               "",
		"javascript:alert(1)":                       "",
		"":                                          "",
	} {
		if got := detailsHref(raw); got != want {
			t.Errorf("%q: %q, want %q", raw, got, want)
		}
	}
	if coverageText(firmware.Coverage{State: firmware.CoverageLegacy, Newest: time.Date(2016, 8, 1, 0, 0, 0, 0, time.UTC),
		MatchedBy: fwcatalog.ByModelName}) != "The vendor catalog lists only legacy entries for this model (newest 2016): likely "+
		"end of support (matched by model name)." {
		t.Error("legacy line")
	}
	for _, st := range []firmware.CoverageState{firmware.CoverageNoBMCType, firmware.CoverageUnknown} {
		if coverageText(firmware.Coverage{State: st}) == "" {
			t.Errorf("%s has no line", st)
		}
	}
}

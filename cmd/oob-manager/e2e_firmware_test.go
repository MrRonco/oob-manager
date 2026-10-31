//go:build e2e

package main

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/firmware/catalog/catalogtest"
	"oob-manager/internal/fwinventory"
	"oob-manager/internal/notify"
)

// firmwareYAML is the firmware stack's minimum list: the R730XD BIOS (2.19.0 in the
// fixture) is below 2.20.0; the BMC's own minimum stays security.min_firmware.
const firmwareYAML = `firmware:
  minimum:
    - { bmc_kind: idrac8, kind: bios, version: "2.20.0", note: "e2e minimum, a deliberately long note that names the BIOS release with the memory training fix so it wraps on a phone" }
`

// iDRAC8 BIOS members of the captured collection, and the same BIOS updated.
const (
	fwCollection = "/redfish/v1/UpdateService/FirmwareInventory"
	biosOld      = fwCollection + "/Current-159-2.19.0"
	biosOldInst  = fwCollection + "/Installed-159-2.19.0"
	biosNew      = fwCollection + "/Current-159-2.20.0"
	biosNewInst  = fwCollection + "/Installed-159-2.20.0"
)

// checkFirmware runs on its own stack (its config has a firmware.minimum rule): both
// mocks are scanned at startup with names from the member documents; the iDRAC8
// backplane image stored on the BMC but never installed and the BIOS below its minimum
// are flagged; a BIOS update on the
// mock plus Re-scan records a change, an audit row and a security notification; the CSV
// parses; and the BMCs saw nothing but reads.
func checkFirmware(t *testing.T) {
	s := startStackWith(t, "127.0.0.1:0", firmwareYAML)
	b := browser{t: t, base: s.base, c: s.client(t)}
	login(t, b, s)
	waitFor(t, "both servers scanned", func() bool {
		return strings.Contains(b.do(http.MethodGet, "/api/v1/firmware", s.token, nil).body, `"scanned_servers":2`)
	})
	// The seed catalog (imported before serve) applies once the scans re-parse it locally.
	waitFor(t, "the Latest column", func() bool { return strings.Contains(b.get("/firmware").body, "Urgent update") })
	fw := b.get("/firmware")
	expectPage(t, fw, "<h1>Firmware</h1>", "Backplane 0", "Broadcom Gigabit Ethernet BCM5720 - 00:00:5E:00:53:00",
		"PERC H730 Mini", "Below minimum", `<span class="nw">minimum 2.20.0</span> · e2e minimum, a deliberately long note`, "Not applied", "(2.25 stored on the BMC, not installed)",
		`href="/firmware" aria-current="page"`, `<span class="cnt">2</span>`, "2025-09", `<th scope="col">Latest</th>`,
		"Update available", "Dell catalog 26.10.22", "The online update check is off")
	if strings.Contains(fw.body, "Component 1") {
		t.Error("a component without a name in the firmware page")
	}
	expectPage(t, b.get("/servers/r730xd/inventory"), `<h2 id="fw-h">Firmware</h2>`, `colspan="9">BIOS</th>`,
		`action="/servers/r730xd/firmware/rescan"`)
	checkFirmwareCSV(t, b, s)

	// The BIOS is updated on the BMC; an operator asks for a re-scan.
	m := s.mocks["r730xd"]
	raw, ok := m.Fixture(fwCollection)
	if !ok {
		t.Fatal("no firmware collection fixture")
	}
	updated := strings.NewReplacer(biosOld, biosNew, biosOldInst, biosNewInst).Replace(string(raw))
	m.SetOverlay(fwCollection, updated)
	expectRedirect(t, b.submit("/firmware", "/servers/r730xd/firmware/rescan", url.Values{"from": {"firmware"}}),
		"/firmware?done=rescan")
	waitFor(t, "the change recorded", func() bool {
		return strings.Contains(b.do(http.MethodGet, "/api/v1/servers/r730xd/firmware", s.token, nil).body,
			`"field":"running","before":"2.19.0","after":"2.20.0"`)
	})
	after := b.get("/servers/r730xd/inventory")
	expectPage(t, after, "Recent changes", "BIOS: running")
	if p := b.do(http.MethodGet, "/api/v1/firmware?server=r730xd&kind=bios", s.token, nil); !strings.Contains(p.body, `"flag":"ok"`) {
		t.Errorf("the updated BIOS is not OK against its minimum: %s", p.body)
	}
	waitFor(t, "firmware change notification", func() bool { return s.hooks.has(notify.ClassSecurity, "firmware changed on 1 component") })

	checkCatalogOnline(t, b, s)
	for id, mock := range s.mocks {
		if n := mock.OtherWrites(); n != 0 {
			t.Errorf("%s: the firmware view sent %d non-GET requests: %+v", id, n, mock.Requests())
		}
		for _, r := range mock.Requests() {
			if strings.Contains(r.Path, "UpdateService") && r.Method != http.MethodGet {
				t.Errorf("%s: %s %s", id, r.Method, r.Path)
			}
		}
	}
	if code := s.stop(); code != 0 {
		t.Fatalf("serve exit %d", code)
	}
	assertAudited(t, s.dbPath, "server.firmware.rescan", "server.firmware.changed")
}

func checkFirmwareCSV(t *testing.T, b browser, s *stack) {
	t.Helper()
	for _, src := range []struct{ path, bearer string }{{"/firmware.csv", ""}, {"/api/v1/firmware.csv?server=r240", s.token}} {
		p := b.do(http.MethodGet, src.path, src.bearer, nil)
		if p.status != http.StatusOK || !strings.HasPrefix(p.header.Get("Content-Type"), "text/csv") ||
			!strings.HasPrefix(p.header.Get("Content-Disposition"), `attachment; filename="firmware_`) {
			t.Fatalf("%s: %d %v", src.path, p.status, p.header)
		}
		recs, err := csv.NewReader(strings.NewReader(p.body)).ReadAll()
		if err != nil || len(recs) < 2 || strings.Join(recs[0], ",") != strings.Join(fwinventory.CSVColumns(), ",") {
			t.Fatalf("%s: %v %q", src.path, err, recs)
		}
	}
	var list struct {
		Data []struct {
			ServerID string `json:"server_id"`
			Flag     string `json:"flag"`
		} `json:"data"`
	}
	p := b.do(http.MethodGet, "/api/v1/firmware?flagged=1", s.token, nil)
	if err := json.Unmarshal([]byte(p.body), &list); err != nil || len(list.Data) != 7 { // 2 posture flags, 5 vendor updates
		t.Fatalf("flagged rows: %v %s", err, p.body)
	}
}

// checkCatalogOnline: the online check is off by default, so nothing reached the
// catalog server (the seed catalog's urgent update was notified from the scans); an admin turns it on in Settings (a fresh step-up: the login just
// happened), the first check imports the signed catalog
// and the urgent update is notified once; Check now re-checks with the ETag (304) and
// notifies nothing new.
func checkCatalogOnline(t *testing.T, b browser, s *stack) {
	t.Helper()
	if hits := s.catalog.requests(); len(hits) != 0 {
		t.Fatalf("the catalog server was asked while the check is off: %v", hits)
	}
	gen := b.get("/settings/general")
	expectPage(t, gen, "Firmware update check", "Vendor firmware catalog", "Upload a catalog",
		catalogtest.RSAKey(t).Fingerprint(), "127.0.0.0/8")
	rev := e2eRevRE.FindStringSubmatch(gen.body)
	if rev == nil {
		t.Fatal("no rev on the General form")
	}
	expectRedirect(t, b.submit("/settings/general", "/settings/general",
		url.Values{"rev": {rev[1]}, "firmware.catalog.enabled": {"on"}}), "/settings/general?done=general")
	gzAsked := func() int {
		n := 0
		for _, p := range s.catalog.requests() {
			if p == "/catalog/Catalog.xml.gz" {
				n++
			}
		}
		return n
	}
	sigAsked := func() bool { return slices.Contains(s.catalog.requests(), "/catalog/Catalog.xml.gz.sign") }
	// The local server's log, not the API, is polled: the token's rate limit is shared.
	// The urgent update was already notified from the seed catalog when the scans
	// recorded it; the online import must not notify it again.
	waitFor(t, "the urgent update notified", func() bool { return s.hooks.has(notify.ClassFirmware, "Urgent firmware update") })
	waitFor(t, "the first online check", sigAsked)
	time.Sleep(500 * time.Millisecond) // let the import finish before asking again
	expectRedirect(t, b.submit("/firmware", "/firmware/catalog/check", nil), "/firmware?done=catalog-check#fw-scans-h")
	waitFor(t, "the conditional re-check", func() bool { return gzAsked() >= 2 })
	var checks string
	for range 20 { // at most 20 API calls: the token's rate limit is shared
		checks = b.do(http.MethodGet, "/api/v1/firmware/catalog", s.token, nil).body
		if strings.Contains(checks, `"result":"not_modified"`) {
			break
		}
		time.Sleep(time.Second)
	}
	if !strings.Contains(checks, `"result":"imported"`) || !strings.Contains(checks, `"result":"not_modified"`) {
		t.Fatalf("checks %s", checks)
	}
	n := 0
	for _, p := range s.hooks.payloads() {
		if p.Class == notify.ClassFirmware {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d firmware notifications, want 1", n)
	}
	for _, p := range s.catalog.requests() {
		if p != "/catalog/Catalog.xml.gz" && p != "/catalog/Catalog.xml.gz.sign" {
			t.Fatalf("asked the catalog server for %s", p)
		}
	}
	api := b.do(http.MethodGet, "/api/v1/firmware?updates=1", s.token, nil).body
	if !strings.Contains(api, `"update":"urgent"`) || !strings.Contains(api, `"enabled":true`) {
		t.Fatalf("API %s", api)
	}
}

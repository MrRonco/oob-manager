package api

import (
	"context"
	"encoding/csv"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/firmware"
	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/fwcatalog"
	"oob-manager/internal/fwinventory"
	"oob-manager/internal/store"
)

type fakeFirmware struct {
	rows    []firmware.Row
	filters []firmware.Filter
	err     error
	status  fwcatalog.Status
	checks  []store.CatalogCheckRow
}

func (f *fakeFirmware) CatalogStatus(context.Context) fwcatalog.Status { return f.status }

func (f *fakeFirmware) CatalogChecks(_ context.Context, limit int) []store.CatalogCheckRow {
	if len(f.checks) > limit {
		return f.checks[:limit]
	}
	return f.checks
}

func (f *fakeFirmware) Table(_ context.Context, flt firmware.Filter) fwinventory.Table {
	f.filters = append(f.filters, flt)
	t := fwinventory.Table{Total: len(f.rows), Flagged: 1, Warn: 1, Generated: t0, Catalog: f.status,
		Servers: []fwinventory.ServerScan{{Scanned: true}, {}}}
	for _, r := range f.rows {
		if flt.Match(r) {
			t.Rows = append(t.Rows, r)
		}
	}
	return t
}

func (f *fakeFirmware) Server(_ context.Context, id string) (fwinventory.ServerView, error) {
	if f.err != nil {
		return fwinventory.ServerView{}, f.err
	}
	if id != "r730xd" {
		return fwinventory.ServerView{}, fwinventory.ErrNotFound
	}
	return fwinventory.ServerView{ServerScan: fwinventory.ServerScan{Info: firmware.ServerInfo{ID: id}, Scanned: true,
		Scan:   store.FirmwareScanRow{ScannedAt: t0, Listed: 21, Complete: true},
		Status: fwinventory.ScanStatus{Enabled: true, Requested: true, Next: t0.Add(24 * time.Hour)}},
		Rows:    f.rows[:1],
		Changes: []store.FirmwareChangeRow{{Name: "BIOS", ComponentID: "159", Field: "running", Before: "2.18.1", After: "2.19.0", SeenAt: t0}}}, nil
}

func fwRows() []firmware.Row {
	return []firmware.Row{
		{Server: firmware.ServerInfo{ID: "r730xd", Name: "R730XD", BMCKind: "idrac8"},
			Component: firmware.Component{Key: firmware.Key{ComponentID: "159"}, Kind: bmc.FirmwareBIOS, Running: "2.19.0"},
			Verdict:   firmware.Verdict{Flags: []firmware.Flag{firmware.FlagBelowMinimum}, Minimum: "2.20.0", MinimumSource: "firmware.minimum"},
			Display:   "@BIOS", LastSeen: t0},
		{Server: firmware.ServerInfo{ID: "r240", Name: "R240", BMCKind: "idrac9"},
			Component: firmware.Component{Key: firmware.Key{ComponentID: "105897", FQDD: "NIC.Embedded.1-1-1"}, Kind: bmc.FirmwareNIC,
				Running: "23.31.1", ReleaseDate: t0.AddDate(-1, 0, 0)},
			Display: "Broadcom NIC"},
	}
}

func TestFirmwareList(t *testing.T) {
	fw := &fakeFirmware{rows: fwRows()}
	a := newTestAPI(t, Deps{Firmware: fw})
	got := decode[struct {
		Data []firmwareRowJSON `json:"data"`
		Meta firmwareMeta      `json:"meta"`
	}](t, do(t, a, http.MethodGet, "/api/v1/firmware?flagged=1", goodToken))
	if len(got.Data) != 1 || got.Data[0].Flag != "below_minimum" || got.Data[0].Minimum != "2.20.0" ||
		got.Data[0].Component != "@BIOS" || got.Meta.Total != 2 || got.Meta.Matched != 1 || got.Meta.ScannedServers != 1 ||
		got.Meta.Catalog.Version != "" || got.Meta.Catalog.Source != "" || got.Data[0].ReleaseDate != nil ||
		got.Data[0].Latest != nil || got.Data[0].Update != "" {
		t.Fatalf("list %+v", got)
	}
	all := do(t, a, http.MethodGet, "/api/v1/firmware", goodToken).Body.String()
	if !strings.Contains(all, `"release_date":"2025-10-20T12:00:00Z"`) || !strings.Contains(all, `"flags":[]`) {
		t.Fatalf("all %s", all)
	}
	if w := do(t, a, http.MethodGet, "/api/v1/firmware?kind=cpu", goodToken); w.Code != http.StatusBadRequest {
		t.Fatalf("bad filter %d", w.Code)
	}
	if w := do(t, a, http.MethodGet, "/api/v1/firmware", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token %d", w.Code)
	}
	if w := do(t, a, http.MethodPost, "/api/v1/firmware", goodToken); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST %d", w.Code)
	}
}

func TestFirmwareCSVExport(t *testing.T) {
	fw := &fakeFirmware{rows: fwRows()}
	a := newTestAPI(t, Deps{Firmware: fw, ExportsPerMinute: 2, Now: func() time.Time { return t0 }})
	w := do(t, a, http.MethodGet, "/api/v1/firmware.csv?server=r730xd", goodToken)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "text/csv; charset=utf-8" ||
		w.Header().Get("Content-Disposition") != `attachment; filename="firmware_r730xd_20261020T1200Z.csv"` {
		t.Fatalf("csv %d %v", w.Code, w.Header())
	}
	recs, err := csv.NewReader(w.Body).ReadAll()
	if err != nil || len(recs) != 2 || recs[1][4] != "'@BIOS" || recs[0][0] != "server_id" {
		t.Fatalf("records %q %v", recs, err)
	}
	if second := do(t, a, http.MethodGet, "/api/v1/firmware.csv", goodToken); second.Code != http.StatusOK {
		t.Fatalf("second export %d", second.Code)
	}
	w = do(t, a, http.MethodGet, "/api/v1/firmware.csv", goodToken)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("third export within a minute %d %v", w.Code, w.Header())
	}
	if w := do(t, a, http.MethodGet, "/api/v1/firmware.csv?q=%00", goodToken); w.Code != http.StatusBadRequest {
		t.Fatalf("bad filter %d", w.Code)
	}
}

func TestFirmwareCSVRowCap(t *testing.T) {
	rows := make([]firmware.Row, fwinventory.MaxCSVRows+1)
	a := newTestAPI(t, Deps{Firmware: &fakeFirmware{rows: rows}})
	if w := do(t, a, http.MethodGet, "/api/v1/firmware.csv", goodToken); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("cap %d", w.Code)
	}
}

func TestServerFirmware(t *testing.T) {
	fw := &fakeFirmware{rows: fwRows()}
	a := newTestAPI(t, Deps{Firmware: fw})
	got := decode[serverFirmwareJSON](t, do(t, a, http.MethodGet, "/api/v1/servers/r730xd/firmware", goodToken))
	if got.ServerID != "r730xd" || !got.Scanning || got.LastScan == nil || !got.LastScan.Equal(t0) || got.Listed != 21 ||
		len(got.Components) != 1 || len(got.Changes) != 1 || got.Changes[0].After != "2.19.0" || got.Truncated {
		t.Fatalf("server firmware %+v", got)
	}
	if w := do(t, a, http.MethodGet, "/api/v1/servers/nope/firmware", goodToken); w.Code != http.StatusNotFound {
		t.Fatalf("unknown %d", w.Code)
	}
	fw.err = errors.New("db down")
	if w := do(t, a, http.MethodGet, "/api/v1/servers/r730xd/firmware", goodToken); w.Code != http.StatusInternalServerError ||
		strings.Contains(w.Body.String(), "db down") {
		t.Fatalf("error %d %s", w.Code, w.Body.String())
	}
}

func TestFirmwareWithoutService(t *testing.T) {
	a := newTestAPI(t, Deps{})
	for _, p := range []string{"/api/v1/firmware", "/api/v1/firmware.csv", "/api/v1/servers/r730xd/firmware"} {
		if w := do(t, a, http.MethodGet, p, goodToken); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
}

func TestFirmwareUpdatesInTheAPI(t *testing.T) {
	rows := fwRows()
	rows[0].Update = firmware.Update{State: firmware.UpdateUrgent, Candidates: 2, MatchedBy: "system_id",
		Latest: catalog.Release{Version: "2.25.2", Criticality: catalog.CriticalityUrgent, Name: "BIOS 2.25.2",
			Date: t0.AddDate(0, -1, 0), DetailsURL: "https://www.dell.com/x", PackagePath: "FOLDER1/BIOS.EXE", RebootRequired: true}}
	pub := t0.AddDate(0, 0, -7)
	fw := &fakeFirmware{rows: rows, status: fwcatalog.Status{Source: "dell", Enabled: true,
		Active:    &store.CatalogImportRow{Version: "26.10.22", PublishedAt: pub, ImportedAt: t0, Signer: "FP"},
		LastCheck: &store.CatalogCheckRow{At: t0, Result: "not_modified"}},
		checks: []store.CatalogCheckRow{{At: t0, Result: "not_modified"}, {At: t0.Add(-time.Hour), Result: "download", Detail: "timed out"}}}
	a := newTestAPI(t, Deps{Firmware: fw})
	got := decode[struct {
		Data []firmwareRowJSON `json:"data"`
		Meta firmwareMeta      `json:"meta"`
	}](t, do(t, a, http.MethodGet, "/api/v1/firmware?updates=1", goodToken))
	if len(got.Data) != 1 || got.Data[0].Update != "urgent" || got.Data[0].Latest == nil ||
		got.Data[0].Latest.Version != "2.25.2" || got.Data[0].Latest.Criticality != "urgent" || !got.Data[0].Latest.RebootRequired ||
		got.Data[0].Latest.Candidates != 2 || got.Data[0].Latest.MatchedBy != "system_id" {
		t.Fatalf("rows %+v", got.Data)
	}
	c := got.Meta.Catalog
	if c.Source != "dell" || c.Version != "26.10.22" || !c.Signed || !c.Enabled || c.Held || c.LastResult != "not_modified" ||
		c.Published == nil || !c.Published.Equal(pub) {
		t.Fatalf("meta.catalog %+v", c)
	}
	st := decode[struct {
		Catalog catalogJSON `json:"catalog"`
		Checks  []struct {
			Result, Detail string
		} `json:"checks"`
	}](t, do(t, a, http.MethodGet, "/api/v1/firmware/catalog", goodToken))
	if st.Catalog.Version != "26.10.22" || len(st.Checks) != 2 || st.Checks[1].Result != "download" || st.Checks[1].Detail != "" {
		t.Fatalf("catalog endpoint %+v", st)
	}
	rec := do(t, a, http.MethodGet, "/api/v1/firmware.csv", goodToken)
	if !strings.Contains(rec.Body.String(), "latest_version,latest_released,latest_criticality,update,catalog_version") ||
		!strings.Contains(rec.Body.String(), ",2.25.2,") || !strings.Contains(rec.Body.String(), ",urgent,urgent,26.10.22") {
		t.Fatalf("csv %s", rec.Body.String())
	}
	if rec := do(t, a, http.MethodGet, "/api/v1/firmware?updates=x", goodToken); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad updates param: %d", rec.Code)
	}
}

package api

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"oob-manager/internal/csvx"
	"oob-manager/internal/firmware"
	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/fwcatalog"
	"oob-manager/internal/fwinventory"
	"oob-manager/internal/store"
	"oob-manager/internal/web"
)

// FirmwareView is the firmware view (fwinventory.Service, docs/tech_doc.md §38).
type FirmwareView interface {
	Table(ctx context.Context, f firmware.Filter) fwinventory.Table
	Server(ctx context.Context, id string) (fwinventory.ServerView, error)
	// CatalogStatus is the update check's status; CatalogChecks its newest checks (at
	// most limit).
	CatalogStatus(ctx context.Context) fwcatalog.Status
	CatalogChecks(ctx context.Context, limit int) []store.CatalogCheckRow
}

// DefaultExportsPerMinute caps CSV exports per token (on top of the token rate limit).
const DefaultExportsPerMinute = 6

type firmwareRowJSON struct {
	ServerID      string     `json:"server_id"`
	ServerName    string     `json:"server_name"`
	BMCKind       string     `json:"bmc_kind"`
	Kind          string     `json:"kind"`
	Component     string     `json:"component"`
	ComponentID   string     `json:"component_id"`
	FQDD          string     `json:"fqdd"`
	Running       string     `json:"running"`
	Previous      string     `json:"previous"`
	Staged        string     `json:"staged"`
	Stored        string     `json:"stored"`
	ReleaseDate   *time.Time `json:"release_date"`
	Updateable    bool       `json:"updateable"`
	Flag          string     `json:"flag"`
	Flags         []string   `json:"flags"`
	Minimum       string     `json:"minimum_version"`
	MinimumSource string     `json:"minimum_source"`
	Identity      string     `json:"identity"`
	FirstSeen     *time.Time `json:"first_seen"`
	LastSeen      *time.Time `json:"last_seen"`
	// Latest is the newest vendor release (null without a catalog or a match); Update is
	// the verdict: none, available, urgent, skipped, cannot_compare, not_in_catalog, or ""
	// when no catalog is in use (plan 08 §14).
	Latest *latestJSON `json:"latest"`
	Update string      `json:"update"`
}

type latestJSON struct {
	Version        string     `json:"version"`
	Released       *time.Time `json:"released"`
	Criticality    string     `json:"criticality"`
	Name           string     `json:"name"`
	DetailsURL     string     `json:"details_url"`
	PackagePath    string     `json:"package_path"`
	RebootRequired bool       `json:"reboot_required"`
	Candidates     int        `json:"candidates"`
	MatchedBy      string     `json:"matched_by"`
}

func latest(u firmware.Update) *latestJSON {
	if u.Latest.Version == "" {
		return nil
	}
	l := u.Latest
	return &latestJSON{Version: l.Version, Released: timePtr(l.Date), Criticality: l.Criticality.String(), Name: l.Name,
		DetailsURL: catalog.SafeDetailsURL(l.DetailsURL), PackagePath: l.PackagePath, RebootRequired: l.RebootRequired, Candidates: u.Candidates,
		MatchedBy: u.MatchedBy}
}

func firmwareRow(r firmware.Row) firmwareRowJSON {
	flags := make([]string, 0, len(r.Flags))
	for _, f := range r.Flags {
		flags = append(flags, string(f))
	}
	return firmwareRowJSON{ServerID: r.Server.ID, ServerName: r.Server.Name, BMCKind: r.Server.BMCKind, Kind: string(r.Kind),
		Component: r.Display, ComponentID: r.ComponentID, FQDD: r.FQDD, Running: r.Running, Previous: r.Previous,
		Staged: r.Staged, Stored: r.Stored, ReleaseDate: timePtr(r.ReleaseDate), Updateable: r.Updateable,
		Flag: string(r.Primary()), Flags: flags, Minimum: r.Minimum, MinimumSource: r.MinimumSource, Identity: r.Identity,
		FirstSeen: timePtr(r.FirstSeen), LastSeen: timePtr(r.LastSeen), Latest: latest(r.Update), Update: string(r.Update.State)}
}

func firmwareRows(rs []firmware.Row) []firmwareRowJSON {
	out := make([]firmwareRowJSON, 0, len(rs))
	for _, r := range rs {
		out = append(out, firmwareRow(r))
	}
	return out
}

type firmwareMeta struct {
	Total          int         `json:"total"`
	Matched        int         `json:"matched"`
	Flagged        int         `json:"flagged"`
	Warn           int         `json:"warn"`
	Updates        int         `json:"updates"`
	Urgent         int         `json:"urgent"`
	ScannedServers int         `json:"scanned_servers"`
	Generated      *time.Time  `json:"generated"`
	Catalog        catalogJSON `json:"catalog"`
}

// catalogJSON is the update check's status (plan 08 §14).
type catalogJSON struct {
	Source     string     `json:"source"`
	Enabled    bool       `json:"enabled"`
	Version    string     `json:"version"`
	Published  *time.Time `json:"published"`
	ImportedAt *time.Time `json:"imported_at"`
	Signed     bool       `json:"signed"`
	Held       bool       `json:"held"`
	CheckedAt  *time.Time `json:"checked_at"`
	LastResult string     `json:"last_result"`
}

func catalogStatus(st fwcatalog.Status) catalogJSON {
	c := catalogJSON{Source: st.Source, Enabled: st.Enabled, Signed: st.Signed(), Held: st.Held != nil}
	if st.Active != nil {
		c.Version, c.Published, c.ImportedAt = st.Active.Version, timePtr(st.Active.PublishedAt), timePtr(st.Active.ImportedAt)
	}
	if st.LastCheck != nil {
		c.CheckedAt, c.LastResult = timePtr(st.LastCheck.At), st.LastCheck.Result
	}
	return c
}

func catalogVersion(st fwcatalog.Status) string {
	if st.Active == nil {
		return ""
	}
	return st.Active.Version
}

// firmwareFilter reads the filter; a value of the wrong shape answers 400.
func firmwareFilter(w http.ResponseWriter, r *http.Request) (firmware.Filter, bool) {
	f, err := fwinventory.ParseFilter(r.URL.Query())
	if err != nil {
		web.WriteProblem(w, r, http.StatusBadRequest, "invalid filter: server, kind, flagged (1), updates (1) and q (at most 64 characters)")
		return firmware.Filter{}, false
	}
	return f, true
}

func (a *API) firmwareView(w http.ResponseWriter, r *http.Request) (FirmwareView, bool) {
	if a.deps.Firmware == nil {
		web.WriteProblem(w, r, http.StatusNotFound, "the firmware view is not available")
		return nil, false
	}
	return a.deps.Firmware, true
}

func (a *API) firmwareList(w http.ResponseWriter, r *http.Request) {
	fv, ok := a.firmwareView(w, r)
	if !ok {
		return
	}
	f, ok := firmwareFilter(w, r)
	if !ok {
		return
	}
	t := fv.Table(r.Context(), f)
	scanned := 0
	for _, s := range t.Servers {
		if s.Scanned {
			scanned++
		}
	}
	writeJSON(w, http.StatusOK, list[firmwareRowJSON]{Data: firmwareRows(t.Rows), Meta: firmwareMeta{Total: t.Total,
		Matched: len(t.Rows), Flagged: t.Flagged, Warn: t.Warn, Updates: t.Updates, Urgent: t.Urgent, ScannedServers: scanned,
		Generated: timePtr(t.Generated), Catalog: catalogStatus(t.Catalog)}})
}

// catalogCheckJSON is one check: its time and result class (the detail text stays out
// of the API).
type catalogCheckJSON struct {
	At     *time.Time `json:"at"`
	Result string     `json:"result"`
}

// firmwareCatalog is the update check's status and its last 20 checks (plan 08 §14).
func (a *API) firmwareCatalog(w http.ResponseWriter, r *http.Request) {
	fv, ok := a.firmwareView(w, r)
	if !ok {
		return
	}
	checks := []catalogCheckJSON{}
	for _, c := range fv.CatalogChecks(r.Context(), 20) {
		checks = append(checks, catalogCheckJSON{At: timePtr(c.At), Result: c.Result})
	}
	writeJSON(w, http.StatusOK, struct {
		Catalog catalogJSON        `json:"catalog"`
		Checks  []catalogCheckJSON `json:"checks"`
	}{catalogStatus(fv.CatalogStatus(r.Context())), checks})
}

func (a *API) firmwareCSV(w http.ResponseWriter, r *http.Request) {
	fv, ok := a.firmwareView(w, r)
	if !ok {
		return
	}
	f, ok := firmwareFilter(w, r)
	if !ok {
		return
	}
	if wait, ok := a.exports.allow(tokenID(r.Context())); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
		web.WriteProblem(w, r, http.StatusTooManyRequests, "export rate limit exceeded")
		return
	}
	t := fv.Table(r.Context(), f)
	var buf bytes.Buffer // at most fwinventory.MaxCSVBytes: a refused export is a 413, never a cut file
	if err := fwinventory.WriteCSV(&buf, t.Rows, catalogVersion(t.Catalog)); err != nil {
		web.WriteProblem(w, r, http.StatusRequestEntityTooLarge, "too many rows for one export; narrow the filter")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", csvx.ContentDisposition(fwinventory.CSVName(f, a.deps.Now())))
	_, _ = w.Write(buf.Bytes())
}

type changeJSON struct {
	Component   string     `json:"component"`
	ComponentID string     `json:"component_id"`
	FQDD        string     `json:"fqdd"`
	Field       string     `json:"field"`
	Before      string     `json:"before"`
	After       string     `json:"after"`
	SeenAt      *time.Time `json:"seen_at"`
}

type serverFirmwareJSON struct {
	ServerID   string            `json:"server_id"`
	Enabled    bool              `json:"scan_enabled"`
	Scanning   bool              `json:"scanning"`
	LastScan   *time.Time        `json:"last_scan"`
	NextScan   *time.Time        `json:"next_scan"`
	ScanError  string            `json:"scan_error"`
	Listed     int               `json:"members_listed"`
	Complete   bool              `json:"complete"`
	Truncated  bool              `json:"truncated"`
	Coverage   coverageJSON      `json:"coverage"`
	Components []firmwareRowJSON `json:"components"`
	Changes    []changeJSON      `json:"changes"`
}

// coverageJSON is how the vendor catalog covers the server (plan 08 §8.3); state ""
// without a catalog.
type coverageJSON struct {
	State      string     `json:"state"`
	SystemID   string     `json:"system_id"`
	MatchedBy  string     `json:"matched_by"`
	Newest     *time.Time `json:"newest_release"`
	Components int        `json:"components"`
	Matched    int        `json:"matched"`
	Updates    int        `json:"updates"`
	Urgent     int        `json:"urgent"`
}

func (a *API) serverFirmware(w http.ResponseWriter, r *http.Request) {
	fv, ok := a.firmwareView(w, r)
	if !ok {
		return
	}
	v, err := fv.Server(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, fwinventory.ErrNotFound):
		web.WriteProblem(w, r, http.StatusNotFound, "unknown server")
		return
	case err != nil:
		a.deps.Logger.Error("api: firmware view failed", "err", err)
		web.WriteProblem(w, r, http.StatusInternalServerError, "the firmware view could not be read")
		return
	}
	out := serverFirmwareJSON{ServerID: v.Info.ID, Enabled: v.Status.Enabled, Scanning: v.Status.Busy(),
		NextScan: timePtr(v.Status.Next), ScanError: v.Status.Error, Listed: v.Scan.Listed, Complete: v.Scan.Complete,
		Truncated: v.Truncated(), Components: firmwareRows(v.Rows), Changes: []changeJSON{},
		Coverage: coverageJSON{State: string(v.Coverage.State), SystemID: v.Coverage.SystemID, MatchedBy: v.Coverage.MatchedBy,
			Newest: timePtr(v.Coverage.Newest), Components: v.Coverage.Components, Matched: v.Coverage.Matched,
			Updates: v.Coverage.Updates, Urgent: v.Coverage.Urgent}}
	if v.Scanned {
		out.LastScan = timePtr(v.Scan.ScannedAt)
	}
	for _, c := range v.Changes {
		out.Changes = append(out.Changes, changeJSON{Component: c.Name, ComponentID: c.ComponentID, FQDD: c.FQDD, Field: c.Field,
			Before: c.Before, After: c.After, SeenAt: timePtr(c.SeenAt)})
	}
	writeJSON(w, http.StatusOK, out)
}

// tokenKey carries the verified token's ID to handlers with their own limits.
type tokenKey struct{}

func tokenID(ctx context.Context) string {
	id, _ := ctx.Value(tokenKey{}).(string)
	return id
}

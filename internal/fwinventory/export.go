package fwinventory

import (
	"errors"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"oob-manager/internal/bmc"
	"oob-manager/internal/csvx"
	"oob-manager/internal/firmware"
)

// Caps of one export: rows (64 members per server makes this thousands of servers) and
// bytes (review S-L7: 10 000 rows of 17 capped cells could otherwise reach tens of MB).
const (
	MaxCSVRows  = 10_000
	MaxCSVBytes = 4 << 20
)

// ErrBadFilter means a filter value has the wrong shape.
var ErrBadFilter = errors.New("fwinventory: invalid filter")

// CSVColumns are the export's columns (docs/tech_doc.md §38); the update check's
// columns are appended so existing positions never move (plan 08 §14).
func CSVColumns() []string {
	return []string{"server_id", "server_name", "bmc_kind", "kind", "component", "component_id", "fqdd", "running",
		"previous", "staged", "stored", "release_date", "updateable", "flag", "minimum_version", "identity",
		"last_seen_utc", "latest_version", "latest_released", "latest_criticality", "update", "catalog_version"}
}

// WriteCSV writes rows through csvx (RFC 4180, formula-injection guard, caps); past
// MaxCSVRows or MaxCSVBytes it fails (csvx.ErrTooManyRows, csvx.ErrTooLarge). Handlers
// write into a buffer first, so a refused export is a 413, never a truncated file.
// catalogVersion is the version of the catalog in use ("" none).
func WriteCSV(w io.Writer, rows []firmware.Row, catalogVersion string) error {
	cw := csvx.NewWriter(w, csvx.Options{MaxRows: MaxCSVRows, MaxCellBytes: 512, MaxBytes: MaxCSVBytes})
	if err := cw.Header(CSVColumns()...); err != nil {
		return err
	}
	for _, r := range rows {
		if err := cw.Row(csvRow(r, catalogVersion)...); err != nil {
			return err
		}
	}
	return cw.Close()
}

func csvRow(r firmware.Row, catalogVersion string) []string {
	rel := ""
	if !r.ReleaseDate.IsZero() {
		rel = r.ReleaseDate.UTC().Format("2006-01-02")
	}
	last := ""
	if !r.LastSeen.IsZero() {
		last = r.LastSeen.UTC().Format(time.RFC3339)
	}
	latestRel := ""
	if !r.Update.Latest.Date.IsZero() {
		latestRel = r.Update.Latest.Date.UTC().Format("2006-01-02")
	}
	if r.Update.State == firmware.UpdateNone {
		catalogVersion = ""
	}
	return []string{r.Server.ID, r.Server.Name, r.Server.BMCKind, string(r.Kind), r.Display, r.ComponentID, r.FQDD,
		r.Running, r.Previous, r.Staged, r.Stored, rel, strconv.FormatBool(r.Updateable), string(r.Primary()),
		r.Minimum, r.Identity, last, r.Update.Latest.Version, latestRel, r.Update.Latest.Criticality.String(),
		string(r.Update.State), catalogVersion}
}

// CSVName is the export's file name: firmware_<fleet|server id>_<yyyymmddThhmmZ>.csv.
func CSVName(f firmware.Filter, at time.Time) string {
	scope := "fleet"
	if f.ServerID != "" {
		scope = f.ServerID
	}
	return csvx.Filename("firmware", scope, at)
}

var filterServer = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// maxFilterText caps the free-text filter.
const maxFilterText = 64

// ParseFilter reads the page's and the API's filter parameters: server (a server ID),
// kind (a firmware kind), flagged ("1", "true" or "on") and q (at most 64 characters of
// plain text). Unknown parameters are ignored; a value of the wrong shape is
// ErrBadFilter, so nothing a request sends reaches a lookup unchecked.
func ParseFilter(q url.Values) (firmware.Filter, error) {
	var f firmware.Filter
	if s := q.Get("server"); s != "" {
		if !filterServer.MatchString(s) {
			return firmware.Filter{}, ErrBadFilter
		}
		f.ServerID = s
	}
	if k := q.Get("kind"); k != "" {
		kind, ok := bmc.ParseFirmwareKind(k)
		if !ok {
			return firmware.Filter{}, ErrBadFilter
		}
		f.Kind = kind
	}
	var err error
	if f.Flagged, err = flagParam(q.Get("flagged")); err != nil {
		return firmware.Filter{}, err
	}
	if f.Updates, err = flagParam(q.Get("updates")); err != nil {
		return firmware.Filter{}, err
	}
	text := strings.TrimSpace(q.Get("q"))
	if utf8.RuneCountInString(text) > maxFilterText || strings.ContainsFunc(text, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
		return firmware.Filter{}, ErrBadFilter
	}
	f.Text = text
	return f, nil
}

// flagParam reads an on/off filter parameter ("" off; 1, true, on).
func flagParam(s string) (bool, error) {
	switch s {
	case "":
		return false, nil
	case "1", "true", "on":
		return true, nil
	default:
		return false, ErrBadFilter
	}
}

// Query is the filter as URL parameters (links, the CSV link of the page).
func Query(f firmware.Filter) url.Values {
	v := url.Values{}
	if f.ServerID != "" {
		v.Set("server", f.ServerID)
	}
	if f.Kind != "" {
		v.Set("kind", string(f.Kind))
	}
	if f.Flagged {
		v.Set("flagged", "1")
	}
	if f.Updates {
		v.Set("updates", "1")
	}
	if f.Text != "" {
		v.Set("q", f.Text)
	}
	return v
}

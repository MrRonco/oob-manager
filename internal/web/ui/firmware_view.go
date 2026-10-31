package ui

import (
	"fmt"
	"net/http"
	"time"

	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
	"oob-manager/internal/firmware"
	"oob-manager/internal/fwinventory"
)

// The firmware view (tech_doc §38): the /firmware fleet page and the Inventory tab's
// Firmware section. Names, versions and release dates are BMC text (cleaned by the
// drivers); html/template escapes them.

// fwRowView is one component row.
type fwRowView struct {
	ServerID, ServerName, Kind, Component string
	Running, Previous, Staged, Stored     string
	Released                              string
	Flags                                 []healthView
	Minimum, MinimumSource, Note          string
	ComponentID, FQDD                     string
	Unnamed                               bool
	Latest                                *fwLatest // the vendor catalog's verdict (nil: no catalog in use)
}

// fwCols hides columns that are empty on every row (UX-19); Details shows the IDs.
// Latest shows while a vendor catalog is in use.
type fwCols struct{ Previous, Staged, Released, Details, Latest bool }

// fwRescan is the Re-scan control: a form (CSRF), the disabled reason, or nothing.
type fwRescan struct {
	ServerID, Name, CSRF, From, Why string
}

// fwScanLine is a server's scan status: "Last scan 14:05 · next in 23 h".
type fwScanLine struct {
	ServerID, Name, Text, ISO string
	Busy                      bool
	Notes                     []string
	Rescan                    *fwRescan
	Coverage                  string // the vendor catalog's line for the server ("" none)
}

type fwGroup struct {
	Label string
	Rows  []fwRowView
}

type fwChangeView struct {
	When, ISO, Component, Field, Before, After string
}

// fwSection is the Inventory tab's Firmware section.
type fwSection struct {
	Groups      []fwGroup
	Cols        fwCols
	Scan        fwScanLine
	DetailsHref string
	Changes     []fwChangeView
	Notice      string
}

// firmwarePageView is /firmware.
type firmwarePageView struct {
	Servers, Kinds []option
	FlaggedOnly    bool
	UpdatesOnly    bool
	Updates        int // newer vendor releases, not skipped
	Urgent         int
	CatalogNotes   []string
	CheckNow       *fwRescan // the vendor catalog's Check now (operator)
	Query          string
	Rows           []fwRowView
	Cols           fwCols
	Total, Shown   string
	Flagged        int
	CSVHref        string
	DetailsHref    string
	Scans          []fwScanLine
	Catalog        string
	Notice         string
	Filtered       bool
	AllHref        string
}

func flagView(f firmware.Flag) healthView {
	switch f {
	case firmware.FlagBelowMinimum, firmware.FlagUpdateUrgent:
		return healthView{Label: f.Label(), Class: "warn"}
	case firmware.FlagNotApplied, firmware.FlagCannotCompare, firmware.FlagStale, firmware.FlagUpdateAvailable:
		return healthView{Label: f.Label(), Class: "info"}
	default:
		return healthView{Label: f.Label(), Class: "ok"}
	}
}

func fwRow(r firmware.Row, now time.Time) fwRowView {
	v := fwRowView{ServerID: r.Server.ID, ServerName: r.Server.Name, Kind: r.Kind.Label(), Component: r.Display,
		Running: r.Running, Previous: r.Previous, Stored: r.Stored, Released: firmware.ReleaseText(r.ReleaseDate, now),
		Minimum: r.Minimum, MinimumSource: r.MinimumSource, Note: r.Note, ComponentID: r.ComponentID, FQDD: r.FQDD,
		Unnamed: !r.Named && r.Display == "Unnamed component (ID "+r.ComponentID+")"}
	if r.Staged != r.Running {
		v.Staged = r.Staged
	}
	for _, f := range r.Flags {
		v.Flags = append(v.Flags, flagView(f))
	}
	if len(v.Flags) == 0 && r.Primary() == firmware.FlagOK {
		v.Flags = []healthView{flagView(firmware.FlagOK)}
	}
	v.Latest = latestView(r.Update, now)
	return v
}

// fwRows renders rows; skip (nil: none) adds a row's admin control.
func fwRows(rows []firmware.Row, now time.Time, details bool, skip func(firmware.Row) *fwSkipForm) ([]fwRowView, fwCols) {
	out := make([]fwRowView, 0, len(rows))
	cols := fwCols{Details: details}
	for _, r := range rows {
		v := fwRow(r, now)
		if v.Latest != nil && skip != nil {
			v.Latest.SkipForm = skip(r)
		}
		cols.Previous = cols.Previous || v.Previous != ""
		cols.Staged = cols.Staged || v.Staged != ""
		cols.Released = cols.Released || v.Released != ""
		cols.Latest = cols.Latest || v.Latest != nil
		out = append(out, v)
	}
	return out, cols
}

// untilText is "in 23 h" / "in 40 min" / "now".
func untilText(next, now time.Time) string {
	d := next.Sub(now)
	switch {
	case d <= time.Minute:
		return "now"
	case d < time.Hour:
		return fmt.Sprintf("in %d min", int(d/time.Minute))
	default:
		return fmt.Sprintf("in %d h", int((d+30*time.Minute)/time.Hour))
	}
}

// scanLine describes a server's scan for sess (the Re-scan control follows the role).
func (s *server) scanLine(sc fwinventory.ServerScan, sess session, from string) fwScanLine {
	now, tf := s.d.Now(), sess.tf()
	l := fwScanLine{ServerID: sc.Info.ID, Name: sc.Info.Name, Busy: sc.Status.Busy()}
	switch {
	case sc.Status.Paused:
		l.Text = "Polling is paused: the BMC certificate does not match its pin. Confirm the new fingerprint in Settings → Servers."
	case !sc.Status.Enabled && !sc.Scanned:
		l.Text = "This BMC has no firmware inventory the app can read."
	case l.Busy:
		l.Text = "Scanning…"
	case sc.Scanned:
		l.Text, l.ISO = "Last scan "+tf.short(sc.Scan.ScannedAt, now), sc.Scan.ScannedAt.UTC().Format(time.RFC3339)
		if !sc.Status.Next.IsZero() {
			l.Text += " · next " + untilText(sc.Status.Next, now)
		}
	default:
		l.Text = "Not scanned yet."
	}
	if sc.Status.Error != "" {
		l.Notes = append(l.Notes, "The last scan failed ("+errorText(bmc.ErrorClass(sc.Status.Error))+"); the previous scan is shown.")
	}
	if sc.Truncated() {
		l.Notes = append(l.Notes, fmt.Sprintf("%d of %d firmware entries were read: the BMC lists more than one scan reads.",
			bmc.MaxFirmwareMembers, sc.Scan.Listed))
	}
	l.Rescan = s.rescanControl(sc, sess, from)
	l.Coverage = coverageText(sc.Coverage)
	return l
}

func (s *server) rescanControl(sc fwinventory.ServerScan, sess session, from string) *fwRescan {
	if !sc.Status.Enabled || sc.Status.Paused || s.d.Authorize(sess.id.Principal(), authz.FirmwareRescan, true) != nil {
		return nil
	}
	c := &fwRescan{ServerID: sc.Info.ID, Name: sc.Info.Name, From: from}
	if sc.Status.Busy() {
		c.Why = "a scan is already waiting or running"
		return c
	}
	c.CSRF = s.csrf.issue(formSettings, sessionBinding(sess.token))
	return c
}

func (s *server) firmwarePage(w http.ResponseWriter, r *http.Request, sess session) {
	if !s.firmwareOn() {
		s.firmwareMissing(w, r)
		return
	}
	f, ok := s.firmwareFilterOf(w, r)
	if !ok {
		return
	}
	details := r.URL.Query().Get("details") == "1"
	t := s.d.Firmware.Table(r.Context(), f)
	now := s.d.Now()
	v := firmwarePageView{FlaggedOnly: f.Flagged, UpdatesOnly: f.Updates, Updates: t.Updates, Urgent: t.Urgent, Query: f.Text,
		Flagged: t.Flagged, Filtered: f.Active(), AllHref: "/firmware", Total: plural(t.Total, "component", "components")}
	v.Catalog, v.CatalogNotes = catalogLine(t.Catalog, sess.tf(), now)
	if !t.Catalog.Enabled && t.Catalog.Online {
		v.CatalogNotes = append(v.CatalogNotes, "The online update check is off (Settings → General).")
	}
	v.CheckNow = s.checkNowControl(t.Catalog, sess)
	v.Rows, v.Cols = fwRows(t.Rows, now, details, func(r firmware.Row) *fwSkipForm { return s.skipControl(r, sess, "firmware") })
	v.Shown = fmt.Sprintf("%d shown", len(v.Rows))
	q := fwinventory.Query(f)
	v.CSVHref = "/firmware.csv?" + q.Encode()
	if details {
		q.Del("details")
	} else {
		q.Set("details", "1")
	}
	v.DetailsHref = "/firmware?" + q.Encode()
	v.Servers = []option{{Value: "", Label: "All servers", Selected: f.ServerID == ""}}
	for _, sc := range t.Servers {
		v.Servers = append(v.Servers, option{Value: sc.Info.ID, Label: sc.Info.Name, Selected: f.ServerID == sc.Info.ID})
		v.Scans = append(v.Scans, s.scanLine(sc, sess, "firmware"))
	}
	v.Kinds = []option{{Value: "", Label: "All kinds", Selected: f.Kind == ""}}
	for _, k := range bmc.FirmwareKinds() {
		v.Kinds = append(v.Kinds, option{Value: string(k), Label: k.Label(), Selected: f.Kind == k})
	}
	v.Notice = firmwareNotice(r.URL.Query().Get("done"), "The table updates")
	d := s.layoutFor(sess, "Firmware", navFirmware, v)
	d.Crumbs = []crumb{{"Overview", "/"}, {Label: "Firmware"}}
	s.render(w, r, http.StatusOK, pageFirmware, d)
}

// firmwareSection is the Inventory tab's Firmware section (nil without the service, or
// when the server is not in the view).
func (s *server) firmwareSection(r *http.Request, v ServerView, sess session) *fwSection {
	if !s.firmwareOn() {
		return nil
	}
	sv, err := s.d.Firmware.Server(r.Context(), v.ID)
	if err != nil {
		return nil
	}
	details := r.URL.Query().Get("details") == "1"
	now := s.d.Now()
	rows, cols := fwRows(sv.Rows, now, details, func(r firmware.Row) *fwSkipForm { return s.skipControl(r, sess, "inventory") })
	sec := &fwSection{Cols: cols, Scan: s.scanLine(sv.ServerScan, sess, "inventory"),
		DetailsHref: "/servers/" + v.ID + "/inventory#fw-h"}
	if !details {
		sec.DetailsHref = "/servers/" + v.ID + "/inventory?details=1#fw-h"
	}
	for _, row := range rows {
		if n := len(sec.Groups); n > 0 && sec.Groups[n-1].Label == row.Kind {
			sec.Groups[n-1].Rows = append(sec.Groups[n-1].Rows, row)
			continue
		}
		sec.Groups = append(sec.Groups, fwGroup{Label: row.Kind, Rows: []fwRowView{row}})
	}
	tf := sess.tf()
	for _, c := range sv.Changes {
		sec.Changes = append(sec.Changes, fwChangeView{When: tf.short(c.SeenAt, now), ISO: c.SeenAt.UTC().Format(time.RFC3339),
			Component: c.Name, Field: c.Field, Before: c.Before, After: c.After})
	}
	sec.Notice = firmwareNotice(r.URL.Query().Get("done"), "This section updates")
	return sec
}

// firmwareNotice is the confirmation after a re-scan or a skip decision.
func firmwareNotice(done, what string) string {
	switch done {
	case "rescan":
		return "Re-scan requested. " + what + " when the scan has finished (usually within a minute)."
	case "catalog-check":
		return "Update check requested. The page shows the result within a minute."
	case "skipped":
		return "Version skipped. It stops flagging until the vendor publishes a newer one."
	case "unskipped":
		return "Skip removed. The update flags again."
	default:
		return ""
	}
}

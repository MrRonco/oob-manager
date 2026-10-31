package ui

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/authz"
	"oob-manager/internal/csvx"
	"oob-manager/internal/firmware"
	"oob-manager/internal/fleet"
	"oob-manager/internal/fwinventory"
)

// Firmware is the read-only firmware view (*fwinventory.Service, tech_doc §38). Reads
// are evaluations of the stored scans: a page view never reaches a BMC. Rescan only asks
// the poller to read the firmware inventory now.
type Firmware interface {
	Table(ctx context.Context, f firmware.Filter) fwinventory.Table
	Server(ctx context.Context, id string) (fwinventory.ServerView, error)
	Rescan(ctx context.Context, a admin.Actor, id string) error
	// WarnCount is the sidebar count (cached by the service: every page shows it).
	WarnCount(ctx context.Context) int
}

// Rates of the firmware view: re-scans (a BMC read each) and CSV exports, per user.
var (
	firmwareRescanRate = RateLimit{Events: 6, Per: time.Minute}
	firmwareExportRate = RateLimit{Events: 6, Per: time.Minute}
)

// firmwareRoutes: the fleet page and its CSV (viewer), and the operator's re-scan
// through probe() (session, CSRF, role, refusals audited; no step-up: it only reads).
func (s *server) firmwareRoutes(mux *http.ServeMux) {
	mux.Handle("GET /firmware", s.page(authz.ViewFirmware, s.firmwarePage))
	mux.Handle("GET /firmware.csv", s.page(authz.ExportFirmware, s.firmwareCSV))
	mux.Handle("POST /servers/{id}/firmware/rescan", s.probe(authz.FirmwareRescan, backFromRescan, s.rescanFirmware))
	s.firmwareUpdateRoutes(mux)
	s.catalogRoutes(mux)
}

// backFromRescan is where a re-scan returns: the Firmware page or the server's
// Inventory tab (a closed choice, never a URL from the form).
func backFromRescan(r *http.Request) string {
	if r.FormValue("from") == "firmware" {
		return "/firmware"
	}
	return "/servers/" + r.PathValue("id") + "/inventory"
}

// firmwareOn reports whether the view is wired.
func (s *server) firmwareOn() bool { return s.d.Firmware != nil }

func (s *server) firmwareMissing(w http.ResponseWriter, r *http.Request) {
	s.errorPage(w, r, http.StatusNotFound, "The firmware view is not available in this installation.")
}

// firmwareFilterOf reads the page's filter; a value of the wrong shape is a 400 page.
func (s *server) firmwareFilterOf(w http.ResponseWriter, r *http.Request) (firmware.Filter, bool) {
	f, err := fwinventory.ParseFilter(r.URL.Query())
	if err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "The filter could not be read. Pick the values from the form.")
		return firmware.Filter{}, false
	}
	return f, true
}

func (s *server) firmwareCSV(w http.ResponseWriter, r *http.Request, sess session) {
	if !s.firmwareOn() {
		s.firmwareMissing(w, r)
		return
	}
	f, ok := s.firmwareFilterOf(w, r)
	if !ok {
		return
	}
	if ok, wait := s.exportLimit.allow("user:" + sess.id.User.ID); !ok {
		s.deny(r, sess, authz.ExportFirmware, "rate_limited")
		setRetryAfter(w, wait)
		s.errorPage(w, r, http.StatusTooManyRequests, "Too many exports in a short time. "+tryAgainIn(wait))
		return
	}
	t := s.d.Firmware.Table(r.Context(), f)
	var buf bytes.Buffer // at most fwinventory.MaxCSVBytes: a refused export is a 413, never a cut file
	catVer := ""
	if t.Catalog.Active != nil {
		catVer = t.Catalog.Active.Version
	}
	if err := fwinventory.WriteCSV(&buf, t.Rows, catVer); err != nil {
		s.errorPage(w, r, http.StatusRequestEntityTooLarge, "Too many rows for one export. Narrow the filter.")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", csvx.ContentDisposition(fwinventory.CSVName(f, s.d.Now())))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

func (s *server) rescanFirmware(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	id := r.PathValue("id")
	if !s.firmwareOn() || !serverIDPattern.MatchString(id) {
		s.firmwareMissing(w, r)
		return
	}
	if _, ok := s.d.Fleet.Server(id); !ok {
		s.serverNotFound(w, r)
		return
	}
	if ok, wait := s.rescanLimit.allow("user:" + sess.id.User.ID); !ok {
		s.deny(r, sess, authz.FirmwareRescan, "rate_limited")
		setRetryAfter(w, wait)
		s.errorPage(w, r, http.StatusTooManyRequests, "Too many re-scans in a short time. "+tryAgainIn(wait))
		return
	}
	err := s.d.Firmware.Rescan(r.Context(), actor(r, sess), id)
	var cd *fwinventory.CooldownError
	switch {
	case errors.As(err, &cd):
		setRetryAfter(w, cd.Left)
		s.errorPage(w, r, http.StatusTooManyRequests, "This server was re-scanned moments ago. "+tryAgainIn(cd.Left))
	case errors.Is(err, fleet.ErrPaused):
		s.errorPage(w, r, http.StatusConflict, "Polling of this server is paused because its certificate no longer matches "+
			"the pinned fingerprint. Confirm the new fingerprint in Settings → Servers first.")
	case errors.Is(err, fwinventory.ErrNotFound), errors.Is(err, fwinventory.ErrUnavailable):
		s.errorPage(w, r, http.StatusNotFound, "This server has no firmware scan.")
	case err != nil:
		s.d.Logger.Error("ui firmware re-scan failed", "server", id, "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "The re-scan could not be requested. Try again.")
	case form.Get("from") == "firmware":
		redirectLocal(w, r, "/firmware?done=rescan")
	default:
		redirectLocal(w, r, "/servers/"+id+"/inventory?done=rescan#fw-h")
	}
}

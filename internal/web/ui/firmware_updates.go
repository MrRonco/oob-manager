package ui

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/authz"
	"oob-manager/internal/firmware"
	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/fwcatalog"
	"oob-manager/internal/fwinventory"
	"oob-manager/internal/store"
)

// FirmwareUpdates is the vendor update check's admin side (*fwcatalog.Checker, plan 08):
// it never reaches a BMC or the network.
type FirmwareUpdates interface {
	Skip(ctx context.Context, a admin.Actor, r fwcatalog.SkipRequest) error
	Unskip(ctx context.Context, a admin.Actor, serverID, componentID, fqdd string) error
}

// firmwareSkipRate caps skip decisions per user (plan 08 §12).
var firmwareSkipRate = RateLimit{Events: 10, Per: time.Minute}

var (
	componentIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	fqddPattern        = regexp.MustCompile(`^[A-Za-z0-9._:-]{0,128}$`)
)

// firmwareUpdateRoutes: skip and unskip, admin with a fresh step-up (the form survives
// the step-up page), CSRF, refusals audited, rate-limited.
func (s *server) firmwareUpdateRoutes(mux *http.ServeMux) {
	mux.Handle("POST /servers/{id}/firmware/skip", s.firmwareChange(s.skipUpdate))
	mux.Handle("POST /servers/{id}/firmware/unskip", s.firmwareChange(s.unskipUpdate))
}

func (s *server) firmwareChange(h changeHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const action = authz.FirmwareSkipUpdate
		sess, form, ok := s.changeForm(w, r, action)
		if !ok || !s.authorizeChange(w, r, sess, action, backFromSkip(r)) {
			return
		}
		if ok, wait := s.skipLimit.allow("user:" + sess.id.User.ID); !ok {
			s.deny(r, sess, action, "rate_limited")
			setRetryAfter(w, wait)
			s.errorPage(w, r, http.StatusTooManyRequests, "Too many changes in a short time. "+tryAgainIn(wait))
			return
		}
		h(w, r, sess, form)
	})
}

// backFromSkip is where a skip returns: the Firmware page or the server's Inventory tab
// (a closed choice, never a URL from the form).
func backFromSkip(r *http.Request) string {
	if r.FormValue("from") == "firmware" {
		return "/firmware"
	}
	return "/servers/" + r.PathValue("id") + "/inventory"
}

func skipDone(r *http.Request, id, done string) string {
	if r.FormValue("from") == "firmware" {
		return "/firmware?done=" + done
	}
	return "/servers/" + id + "/inventory?done=" + done + "#fw-h"
}

// updateRow finds the component's row; the form names it by component ID and FQDD.
func (s *server) updateRow(w http.ResponseWriter, r *http.Request, form url.Values) (firmware.Row, bool) {
	id, cid, fqdd := r.PathValue("id"), form.Get("component"), form.Get("fqdd")
	if !s.firmwareOn() || s.d.FirmwareUpdates == nil || !serverIDPattern.MatchString(id) {
		s.firmwareMissing(w, r)
		return firmware.Row{}, false
	}
	if !componentIDPattern.MatchString(cid) || !fqddPattern.MatchString(fqdd) {
		s.errorPage(w, r, http.StatusBadRequest, "The form could not be read. Reload the page.")
		return firmware.Row{}, false
	}
	sv, err := s.d.Firmware.Server(r.Context(), id)
	if errors.Is(err, fwinventory.ErrNotFound) {
		s.serverNotFound(w, r)
		return firmware.Row{}, false
	}
	if err != nil {
		s.d.Logger.Error("ui firmware view failed", "server", id, "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "The firmware view could not be read. Try again.")
		return firmware.Row{}, false
	}
	for _, row := range sv.Rows {
		if row.ComponentID == cid && row.FQDD == fqdd {
			return row, true
		}
	}
	s.errorPage(w, r, http.StatusConflict, msgUpdateChanged)
	return firmware.Row{}, false
}

const msgUpdateChanged = "This component's update changed since the page was loaded. Reload the page and try again."

func (s *server) skipUpdate(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	row, ok := s.updateRow(w, r, form)
	if !ok {
		return
	}
	if !row.Update.Newer() || row.Update.Latest.Version != form.Get("version") {
		s.errorPage(w, r, http.StatusConflict, msgUpdateChanged)
		return
	}
	err := s.d.FirmwareUpdates.Skip(r.Context(), actor(r, sess), fwcatalog.SkipRequest{ServerID: row.Server.ID,
		ComponentID: row.ComponentID, FQDD: row.FQDD, Version: row.Update.Latest.Version, Comment: form.Get("comment")})
	switch {
	case errors.Is(err, fwcatalog.ErrBadSkip):
		s.errorPage(w, r, http.StatusUnprocessableEntity, "Give a reason on one line, 500 bytes at most (fewer characters with accents or symbols).")
	case errors.Is(err, fwcatalog.ErrBadVersion):
		s.errorPage(w, r, http.StatusUnprocessableEntity, "This version cannot be skipped (longer than 64 characters).")
	case err != nil:
		s.d.Logger.Error("ui firmware skip failed", "server", row.Server.ID, "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "The version could not be skipped. Try again.")
	default:
		redirectLocal(w, r, skipDone(r, row.Server.ID, "skipped"))
	}
}

func (s *server) unskipUpdate(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	row, ok := s.updateRow(w, r, form)
	if !ok {
		return
	}
	err := s.d.FirmwareUpdates.Unskip(r.Context(), actor(r, sess), row.Server.ID, row.ComponentID, row.FQDD)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.errorPage(w, r, http.StatusConflict, msgUpdateChanged)
	case err != nil:
		s.d.Logger.Error("ui firmware unskip failed", "server", row.Server.ID, "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "The skip could not be removed. Try again.")
	default:
		redirectLocal(w, r, skipDone(r, row.Server.ID, "unskipped"))
	}
}

// detailsHref allows only https links on dell.com (plan 08 §10); anything else is text.
func detailsHref(raw string) string { return catalog.SafeDetailsURL(raw) }

// fwLatest is a row's Latest cell.
type fwLatest struct {
	Version, Criticality, Class, Released, Href, Name, Text string
	StoredNote                                              bool // the BMC already holds it
	Skip                                                    *firmware.Skip
	SkipForm                                                *fwSkipForm
}

// fwSkipForm is the admin's Skip or Unskip control on a row.
type fwSkipForm struct {
	ServerID, ComponentID, FQDD, Version, Anchor, CSRF, From string
	Unskip                                                   bool
}

// latestView renders a row's update; nil when no catalog is in use.
func latestView(u firmware.Update, now time.Time) *fwLatest {
	l := &fwLatest{Version: u.Latest.Version, Name: u.Latest.Name, Href: detailsHref(u.Latest.DetailsURL),
		Released: firmware.ReleaseText(u.Latest.Date, now), Skip: u.Skip}
	if u.Latest.Criticality.Valid() {
		l.Criticality = u.Latest.Criticality.Label()
	}
	switch u.State {
	case firmware.UpdateNone:
		return nil
	case firmware.UpdateUrgent:
		l.Class = "warn"
	case firmware.UpdateAvailable:
		l.Class = "info"
	case firmware.UpdateCurrent:
		l.Text = "Up to date"
	case firmware.UpdateSkipped:
		l.Text = "Skipped"
	case firmware.UpdateCannotCompare:
		l.Text = "Cannot compare"
	case firmware.UpdateNotInCatalog:
		l.Text, l.Version = "Not in the vendor catalog", ""
	}
	l.StoredNote = u.StoredIsLatest && u.Newer()
	if u.State != firmware.UpdateSkipped {
		l.Skip = nil
	}
	if !u.Newer() { // the criticality and date describe a release still to install
		l.Criticality, l.Released = "", ""
	}
	return l
}

// skipControl is the admin's form on a row with a newer release or a skip.
func (s *server) skipControl(r firmware.Row, sess session, from string) *fwSkipForm {
	if s.d.FirmwareUpdates == nil || (!r.Update.Newer() && r.Update.State != firmware.UpdateSkipped) ||
		s.d.Authorize(sess.id.Principal(), authz.FirmwareSkipUpdate, true) != nil {
		return nil
	}
	return &fwSkipForm{ServerID: r.Server.ID, ComponentID: r.ComponentID, FQDD: r.FQDD, Version: r.Update.Latest.Version,
		Anchor: anchorOf(r.Server.ID + "-" + r.ComponentID + "-" + r.FQDD), From: from,
		Unskip: r.Update.State == firmware.UpdateSkipped, CSRF: s.csrf.issue(formSettings, sessionBinding(sess.token))}
}

// anchorOf makes an element ID from free text (letters, digits and dashes) plus a short
// hash of the text, so "A.B" and "A-B" stay distinct.
func anchorOf(s string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return anchorText(s) + "-" + strconv.FormatUint(uint64(h.Sum32()), 36)
}

func anchorText(s string) string {
	b := make([]byte, 0, len(s))
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b = append(b, c)
		case c >= 'A' && c <= 'Z':
			b = append(b, c+32)
		default:
			b = append(b, '-')
		}
	}
	return "fwu-" + string(b)
}

// catalogLine is the update check's status line and its notes (plan 08 §10).
func catalogLine(st fwcatalog.Status, tf timeFmt, now time.Time) (string, []string) {
	var notes []string
	if st.Held != nil {
		notes = append(notes, "A newer catalog ("+st.Held.Version+") lists far fewer components than the one in use and is "+
			"held until an admin confirms it.")
	}
	if c := st.LastCheck; c != nil && checkFailed(c.Result) {
		notes = append(notes, "The last check failed ("+checkResultText(c.Result)+", "+tf.short(c.At, now)+"); the catalog "+
			"in use stays.")
	}
	if st.Active == nil {
		if st.Enabled && st.Online && st.LastCheck == nil {
			// Just switched on: the first check runs within a minute or two.
			return "The first online check is running; no vendor catalog is imported yet. Refresh in a minute.", notes
		}
		return "No vendor catalog is imported, so firmware updates are not checked.", notes
	}
	line := "Dell catalog " + st.Active.Version
	if !st.Active.PublishedAt.IsZero() {
		line += " (published " + st.Active.PublishedAt.UTC().Format("2006-01-02") + ")"
	}
	line += ", imported " + tf.short(st.Active.ImportedAt, now)
	if !st.Signed() {
		line += " · unsigned catalog (accepted by configuration)"
	}
	return line + ".", notes
}

func checkFailed(result string) bool {
	switch result {
	case "imported", "held", "not_modified", "disabled":
		return false
	default:
		return true
	}
}

func checkResultText(result string) string {
	switch result {
	case "download":
		return "download"
	case "size":
		return "too large"
	case "signature":
		return "signature check"
	case "untrusted_key":
		return "signed by an untrusted key"
	case "parse":
		return "not a valid catalog"
	default:
		return result
	}
}

// coverageText is a server's catalog line (plan 08 §8.3).
func coverageText(c firmware.Coverage) string {
	by := ""
	if c.MatchedBy == fwcatalog.ByModelName {
		by = " (matched by model name)"
	}
	switch c.State {
	case firmware.CoverageNoBMCType:
		return "No vendor catalog for this BMC type."
	case firmware.CoverageUnknown:
		return "The model could not be identified for the update check; an admin can set firmware.catalog.systems in config.yaml."
	case firmware.CoverageNotListed:
		return "The vendor catalog doesn't list this model, so updates can't be checked (end of support, or a model the catalog omits)."
	case firmware.CoverageLegacy:
		return "The vendor catalog lists only legacy entries for this model (newest " + c.Newest.UTC().Format("2006") +
			"): likely end of support" + by + "."
	case firmware.CoverageNormal:
		return fmt.Sprintf("%d of %d components matched · %s%s", c.Matched, c.Components, updatesText(c.Updates, c.Urgent), by)
	default:
		return ""
	}
}

func updatesText(n, urgent int) string {
	t := plural(n, "update", "updates")
	if urgent > 0 {
		t += fmt.Sprintf(" (%d urgent)", urgent)
	}
	return t
}

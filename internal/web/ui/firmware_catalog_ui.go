package ui

import (
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/authz"
	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/fwcatalog"
)

// The firmware update check's controls (plan 08 §10): Check now on /firmware (operator),
// and on Settings › General the catalog panel: the file-only keys read-only, an upload
// form and the confirmation of a held catalog (admin, fresh step-up). Turning the online
// check on is a General key (step-up like every General change, audited twice).

// FirmwareCatalog is the update check's operator and admin side (*fwcatalog.Checker).
type FirmwareCatalog interface {
	Status(ctx context.Context) fwcatalog.Status
	File() fwcatalog.FileSettings
	CheckNow(ctx context.Context, a admin.Actor) error
	Upload(ctx context.Context, a admin.Actor, gz io.Reader, sig []byte) (fwcatalog.Result, error)
	ConfirmHeld(ctx context.Context, a admin.Actor, importID int64) error
	EnabledChanged(ctx context.Context, a admin.Actor, before, after bool)
}

// catalogUploadRate caps uploads per user (plan 08 §12); maxSigUpload the signature file.
var catalogUploadRate = RateLimit{Events: 1, Per: time.Minute}

const (
	maxSigUpload     = 4 << 10
	maxUploadRequest = fwcatalog.MaxCatalogBytes + maxSigUpload + 64<<10 // two files and the form fields
)

func (s *server) catalogRoutes(mux *http.ServeMux) {
	mux.Handle("POST /firmware/catalog/check", s.probe(authz.FirmwareCatalogCheck,
		func(*http.Request) string { return "/firmware" }, s.checkCatalogNow))
	mux.Handle("POST /settings/catalog/upload", http.HandlerFunc(s.uploadCatalog))
	mux.Handle("POST /settings/catalog/confirm", s.change(authz.FirmwareCatalogUpload, backToGeneral, s.confirmCatalog))
}

func (s *server) catalogOn() bool { return s.d.FirmwareCatalog != nil }

func (s *server) checkCatalogNow(w http.ResponseWriter, r *http.Request, sess session, _ url.Values) {
	if !s.catalogOn() {
		s.firmwareMissing(w, r)
		return
	}
	err := s.d.FirmwareCatalog.CheckNow(r.Context(), actor(r, sess))
	var wait *fwcatalog.WaitError
	switch {
	case err == nil:
		redirectLocal(w, r, "/firmware?done=catalog-check#fw-scans-h")
	case errors.As(err, &wait):
		s.deny(r, sess, authz.FirmwareCatalogCheck, "rate_limited")
		setRetryAfter(w, wait.Left)
		s.errorPage(w, r, http.StatusTooManyRequests, "The catalog was checked moments ago. "+tryAgainIn(wait.Left))
	case errors.Is(err, fwcatalog.ErrCheckOff), errors.Is(err, fwcatalog.ErrNoOnline):
		s.deny(r, sess, authz.FirmwareCatalogCheck, "disabled")
		s.errorPage(w, r, http.StatusConflict, "The online update check is off. An admin can turn it on in Settings → General.")
	default:
		s.d.Logger.Error("ui catalog check failed", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "The check could not be requested. Try again.")
	}
}

// uploadCatalog imports an uploaded catalog, streamed: no temporary copy of the form is
// written (the container's /tmp is a small tmpfs). A multipart form cannot be kept across
// the step-up page, so the role and the step-up are checked before the body is read (the
// panel shows the form only with a fresh step-up). The form's parts must come in order:
// the CSRF token, then the signature, then the catalog, which streams into the import.
func (s *server) uploadCatalog(w http.ResponseWriter, r *http.Request) {
	const action = authz.FirmwareCatalogUpload
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	if !s.catalogOn() || s.d.Admin == nil || s.d.AuditLog == nil {
		s.errorPage(w, r, http.StatusNotFound, "The firmware update check is not available in this installation.")
		return
	}
	switch err := s.d.Authorize(sess.id.Principal(), action, s.d.Auth.StepUpFresh(sess.id.Session)); {
	case errors.Is(err, authz.ErrStepUpRequired):
		s.deny(r, sess, action, "stepup_required")
		http.Redirect(w, r, "/stepup?"+url.Values{"next": {"/settings/general"}}.Encode(), http.StatusSeeOther)
		return
	case err != nil:
		s.deny(r, sess, action, "forbidden")
		s.errorPage(w, r, http.StatusForbidden, "Only an admin can upload a catalog.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadRequest)
	mr, err := r.MultipartReader()
	if err != nil || !s.uploadCSRF(mr, sess) {
		s.deny(r, sess, action, "csrf")
		s.errorPage(w, r, http.StatusForbidden, msgFormExpired)
		return
	}
	if ok, wait := s.uploadLimit.allow("user:" + sess.id.User.ID); !ok {
		s.deny(r, sess, action, "rate_limited")
		setRetryAfter(w, wait)
		s.errorPage(w, r, http.StatusTooManyRequests, "One catalog upload a minute. "+tryAgainIn(wait))
		return
	}
	s.importUpload(w, r, sess, mr)
}

// uploadCSRF reads the first part, which must be the CSRF token, and checks it.
func (s *server) uploadCSRF(mr *multipart.Reader, sess session) bool {
	p, err := mr.NextPart()
	if err != nil || p.FormName() != csrfField {
		return false
	}
	tok, err := io.ReadAll(io.LimitReader(p, 512))
	return err == nil && s.csrf.verify(string(tok), formSettings, sessionBinding(sess.token))
}

func (s *server) importUpload(w http.ResponseWriter, r *http.Request, sess session, mr *multipart.Reader) {
	var sig []byte
	for {
		p, err := mr.NextPart()
		if err != nil {
			s.uploadFailed(w, r, sess, err)
			return
		}
		switch p.FormName() {
		case "signature":
			if sig, err = io.ReadAll(io.LimitReader(p, maxSigUpload+1)); err != nil || len(sig) > maxSigUpload {
				s.renderGeneral(w, r, sess, http.StatusRequestEntityTooLarge, nil, "The signature file is larger than 4 KiB.", "")
				return
			}
		case "catalog":
			res, err := s.d.FirmwareCatalog.Upload(r.Context(), actor(r, sess), p, sig)
			if err != nil {
				s.uploadFailed(w, r, sess, err)
				return
			}
			done := "catalog-imported"
			if res.State == "held" {
				done = "catalog-held"
			}
			redirectLocal(w, r, "/settings/general?done="+done+"#cat-h")
			return
		}
	}
}

// uploadFailed answers a refused upload: too large (413), no catalog part (400), or the
// import's class.
func (s *server) uploadFailed(w http.ResponseWriter, r *http.Request, sess session, err error) {
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge) || catalog.Class(err) == "size":
		s.renderGeneral(w, r, sess, http.StatusRequestEntityTooLarge, nil, "The catalog was not imported: "+
			"it is too large (16 MiB compressed at most).", "")
	case errors.Is(err, io.EOF):
		s.renderGeneral(w, r, sess, http.StatusBadRequest, nil, "Choose the catalog file (Catalog.xml.gz).", "")
	default:
		s.renderGeneral(w, r, sess, http.StatusUnprocessableEntity, nil, "The catalog was not imported: "+catalogErrorText(err), "")
	}
}

// catalogErrorText is the admin-facing reason of a refused catalog (the class, never
// the file's content).
func catalogErrorText(err error) string {
	switch catalog.Class(err) {
	case "signature":
		if errors.Is(err, fwcatalog.ErrUnsigned) {
			return "it has no signature (choose the .sign file too; unsigned catalogs need firmware.catalog.allow_unsigned in config.yaml)."
		}
		return "the signature does not match the catalog."
	case "untrusted_key":
		return "it is signed by a key that is not trusted (" + keyIDOf(err) + "). Add the key to firmware.catalog.extra_keys_file if it is genuine."
	case "size":
		return "it is too large (16 MiB compressed at most)."
	case "parse":
		return "it is not a valid vendor catalog."
	default:
		return "it could not be read. Try again."
	}
}

// keyIDOf extracts "key ID XXXXXXXXXXXXXXXX" from an untrusted-key error (our own text).
func keyIDOf(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, "key ID "); i >= 0 && len(msg) >= i+23 {
		return msg[i : i+23]
	}
	return "unknown key"
}

func (s *server) confirmCatalog(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	if !s.catalogOn() {
		s.firmwareMissing(w, r)
		return
	}
	id, perr := strconv.ParseInt(form.Get("import"), 10, 64)
	if perr != nil || id <= 0 {
		s.errorPage(w, r, http.StatusBadRequest, "The form could not be read. Reload the page.")
		return
	}
	switch err := s.d.FirmwareCatalog.ConfirmHeld(r.Context(), actor(r, sess), id); {
	case err == nil:
		redirectLocal(w, r, "/settings/general?done=catalog-confirmed#cat-h")
	case errors.Is(err, fwcatalog.ErrNothingHeld):
		s.errorPage(w, r, http.StatusConflict, "No catalog is waiting for confirmation any more.")
	default:
		s.d.Logger.Error("ui catalog confirm failed", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "The catalog could not be confirmed. Try again.")
	}
}

// catalogPanel is the Settings › General catalog panel.
type catalogPanel struct {
	Status       string
	Notes        []string
	Host         string
	File         fwcatalog.FileSettings
	Fingerprints string
	HeldVersion  string
	HeldID       int64
	CSRF         string // set for an admin: the upload and confirm forms
	StepUpFresh  bool   // the upload form is shown only with a fresh step-up (files are not kept)
}

func (s *server) catalogPanel(ctx context.Context, sess session) *catalogPanel {
	if !s.catalogOn() {
		return nil
	}
	st := s.d.FirmwareCatalog.Status(ctx)
	p := &catalogPanel{Host: st.Host, File: s.d.FirmwareCatalog.File()}
	p.Status, p.Notes = catalogLine(st, sess.tf(), s.d.Now())
	p.Fingerprints = strings.Join(p.File.Fingerprints, ", ")
	if st.Held != nil {
		p.HeldVersion, p.HeldID = st.Held.Version, st.Held.ID
	}
	if s.d.Authorize(sess.id.Principal(), authz.FirmwareCatalogUpload, true) == nil {
		p.CSRF = s.csrf.issue(formSettings, sessionBinding(sess.token))
		p.StepUpFresh = s.d.Auth.StepUpFresh(sess.id.Session)
	}
	return p
}

// checkNowControl is the Check now button on /firmware (operator, while the check is on).
func (s *server) checkNowControl(st fwcatalog.Status, sess session) *fwRescan {
	if !s.catalogOn() || !st.Online || s.d.Authorize(sess.id.Principal(), authz.FirmwareCatalogCheck, true) != nil {
		return nil
	}
	c := &fwRescan{Name: "the vendor catalog"}
	if !st.Enabled {
		c.Why = "the online check is off (Settings → General)"
		return c
	}
	c.CSRF = s.csrf.issue(formSettings, sessionBinding(sess.token))
	return c
}

// catalogEnabledChange audits a change of the online check switch after a General save.
func (s *server) catalogEnabledChange(ctx context.Context, a admin.Actor, field, before, after string) {
	if s.catalogOn() && field == "firmware.catalog.enabled" && before != after {
		s.d.FirmwareCatalog.EnabledChanged(ctx, a, before == "on", after == "on")
	}
}

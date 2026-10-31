package ui

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/fwcatalog"
	"oob-manager/internal/store"
	"oob-manager/internal/web"
)

// fakeCatalog is the update check's operator and admin side.
type fakeCatalog struct {
	mu        sync.Mutex
	status    fwcatalog.Status
	checks    []string
	checkErr  error
	uploads   []string // user/size/sig size
	uploadErr error
	confirms  int
	enabled   []string
}

func (f *fakeCatalog) Status(context.Context) fwcatalog.Status { return f.status }
func (f *fakeCatalog) File() fwcatalog.FileSettings {
	return fwcatalog.FileSettings{Fingerprints: []string{"4172E2CE955A1776A5E61BB7CA77951D23B66A9D"}, AllowedNetworks: []string{"192.0.2.0/24"}}
}

func (f *fakeCatalog) CheckNow(_ context.Context, a admin.Actor) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.checkErr != nil {
		return f.checkErr
	}
	f.checks = append(f.checks, a.Username)
	return nil
}

func (f *fakeCatalog) Upload(_ context.Context, a admin.Actor, gz io.Reader, sig []byte) (fwcatalog.Result, error) {
	b, _ := io.ReadAll(gz)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.uploadErr != nil {
		return fwcatalog.Result{}, f.uploadErr
	}
	f.uploads = append(f.uploads, fmt.Sprintf("%s/%d/%d", a.Username, len(b), len(sig)))
	return fwcatalog.Result{State: store.CatalogActive}, nil
}

func (f *fakeCatalog) ConfirmHeld(_ context.Context, _ admin.Actor, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id != 7 {
		return fwcatalog.ErrNothingHeld
	}
	f.confirms++
	return nil
}

func (f *fakeCatalog) EnabledChanged(_ context.Context, a admin.Actor, before, after bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = append(f.enabled, fmt.Sprintf("%s:%v->%v", a.Username, before, after))
}

func newCatalogEnv(t *testing.T) (*fwEnv, *fakeCatalog) {
	t.Helper()
	fw := newFakeFirmware()
	cat := &fakeCatalog{status: fwcatalog.Status{Source: "dell", Online: true, Enabled: true, Host: "downloads.example.com",
		Active: &store.CatalogImportRow{Version: "26.10.22", Signer: "FP", ImportedAt: fwNow},
		Held:   &store.CatalogImportRow{ID: 7, Version: "26.11.01"}}}
	fw.catalog = cat.status
	e, _ := newGeneralEnv(t, "")
	e.deps.Firmware, e.deps.FirmwareCatalog = fw, cat
	app, err := New(e.deps)
	must(t, err)
	e.handler, err = web.NewHandler(app, web.Options{Logger: quiet()})
	must(t, err)
	return &fwEnv{settingsEnv: e, fw: fw}, cat
}

// multipartPost posts the upload form with the page's CSRF token.
func multipartPost(t *testing.T, c *client, csrf string, gz, sig []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField(csrfField, csrf)
	if sig != nil {
		w, _ := mw.CreateFormFile("signature", "Catalog.xml.gz.sign")
		_, _ = w.Write(sig)
	}
	if gz != nil {
		w, _ := mw.CreateFormFile("catalog", "Catalog.xml.gz")
		_, _ = w.Write(gz)
	}
	_ = mw.Close()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://oob.test/settings/catalog/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.RemoteAddr = c.ip + ":50000"
	for k, v := range c.jar {
		req.AddCookie(&http.Cookie{Name: k, Value: v, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	rec := httptest.NewRecorder()
	c.h.handler.ServeHTTP(rec, req)
	return rec
}

func TestCatalogCheckNow(t *testing.T) {
	e, cat := newCatalogEnv(t)
	op := e.userClient(t, "olga", authz.RoleOperator, "192.0.2.21")
	page := result(op.get("/firmware")).status(t, http.StatusOK)
	page.contains(t, `action="/firmware/catalog/check"`, "Check the vendor catalog now")
	result(op.submit("/firmware", "/firmware/catalog/check", nil)).status(t, http.StatusSeeOther).
		location(t, "/firmware?done=catalog-check#fw-scans-h")
	cat.checkErr = &fwcatalog.WaitError{Left: 3 * time.Minute}
	result(op.submit("/firmware", "/firmware/catalog/check", nil)).status(t, http.StatusTooManyRequests)
	cat.checkErr = fwcatalog.ErrCheckOff
	result(op.submit("/firmware", "/firmware/catalog/check", nil)).status(t, http.StatusConflict)
	if len(cat.checks) != 1 || cat.checks[0] != "olga" {
		t.Fatalf("checks %v", cat.checks)
	}
	viewer := e.userClient(t, "vera", authz.RoleViewer, "192.0.2.22")
	result(viewer.get("/firmware")).status(t, http.StatusOK).lacks(t, `action="/firmware/catalog/check"`)
	result(viewer.do(http.MethodPost, "/firmware/catalog/check", url.Values{})).status(t, http.StatusForbidden)
}

func TestCatalogSettingsPanelUploadAndConfirm(t *testing.T) {
	e, cat := newCatalogEnv(t)
	adm := e.adminClient()
	gen := result(adm.get("/settings/general")).status(t, http.StatusOK)
	gen.contains(t, "Firmware update check", "https://downloads.example.com", "Check the vendor catalog online",
		"Vendor firmware catalog", "4172E2CE955A1776A5E61BB7CA77951D23B66A9D", "192.0.2.0/24", `enctype="multipart/form-data"`,
		"Use the held catalog 26.11.01")
	csrf := csrfForAny(t, gen.rec.Body.String(), "/settings/catalog/upload")
	result(multipartPost(t, adm, csrf, []byte("gzdata"), []byte("sig"))).status(t, http.StatusSeeOther).
		location(t, "/settings/general?done=catalog-imported#cat-h")
	if len(cat.uploads) != 1 || cat.uploads[0] != "morgan/6/3" {
		t.Fatalf("uploads %v", cat.uploads)
	}
	// One upload a minute per user.
	result(multipartPost(t, adm, csrf, []byte("gz"), nil)).status(t, http.StatusTooManyRequests)
	e.clock.Advance(61 * time.Second)
	cat.uploadErr = fmt.Errorf("%w: key ID 0123456789ABCDEF", catalog.ErrUntrustedKey)
	result(multipartPost(t, adm, csrf, []byte("gz"), []byte("s"))).status(t, http.StatusUnprocessableEntity).
		contains(t, "not trusted (key ID 0123456789ABCDEF)")
	e.clock.Advance(61 * time.Second)
	result(multipartPost(t, adm, "bogus", []byte("gz"), nil)).status(t, http.StatusForbidden)
	result(adm.submit("/settings/general", "/settings/catalog/confirm", url.Values{"import": {"7"}})).status(t, http.StatusSeeOther).
		location(t, "/settings/general?done=catalog-confirmed#cat-h")
	result(adm.submit("/settings/general", "/settings/catalog/confirm", url.Values{"import": {"8"}})).status(t, http.StatusConflict)
	e.clock.Advance(61 * time.Second)
	result(multipartPost(t, adm, csrf, nil, []byte("s"))).status(t, http.StatusBadRequest)
	e.clock.Advance(61 * time.Second)
	result(multipartPost(t, adm, csrf, make([]byte, maxUploadRequest+1), nil)).status(t, http.StatusRequestEntityTooLarge)
	if cat.confirms != 1 {
		t.Fatalf("confirms %d", cat.confirms)
	}
	// A stale step-up asks for a code; the files are not kept, and the panel offers the
	// code first instead of the file inputs.
	e.clock.Advance(6 * time.Minute)
	result(adm.get("/settings/general")).contains(t, "Confirm your authenticator code to upload").
		lacks(t, `enctype="multipart/form-data"`)
	rec := multipartPost(t, adm, csrf, []byte("gz"), nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/stepup?next=%2Fsettings%2Fgeneral" {
		t.Fatalf("stale step-up: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if r, ok := e.findAudit(string(authz.FirmwareCatalogUpload), audit.ResultDenied); !ok || r.ErrorClass != "stepup_required" {
		t.Fatalf("refusal not audited: %+v", r)
	}
	op := e.userClient(t, "olga", authz.RoleOperator, "192.0.2.21")
	result(op.get("/settings/general")).lacks(t, "/settings/catalog/upload")
	result(multipartPost(t, op, "x", []byte("gz"), nil)).status(t, http.StatusForbidden)
}

func TestEnablingTheCatalogCheckIsAudited(t *testing.T) {
	e, cat := newCatalogEnv(t)
	adm := e.adminClient()
	gen := adm.get("/settings/general").Body.String()
	m := regexp.MustCompile(`name="rev" value="(\d+)"`).FindStringSubmatch(gen)
	if m == nil {
		t.Fatal("no rev")
	}
	result(adm.submit("/settings/general", "/settings/general", url.Values{"rev": {m[1]}, "firmware.catalog.enabled": {"on"}})).
		status(t, http.StatusSeeOther)
	if len(cat.enabled) != 1 || cat.enabled[0] != "morgan:false->true" {
		t.Fatalf("enabled changes %v", cat.enabled)
	}
}

// Right after the online check is switched on, before its first check finishes, the line
// says the check is running instead of "not checked" (v0.9.1).
func TestCatalogLineFirstCheckRunning(t *testing.T) {
	now := time.Date(2026, 10, 29, 19, 0, 0, 0, time.UTC)
	running, _ := catalogLine(fwcatalog.Status{Enabled: true, Online: true}, timeFmt{loc: time.UTC}, now)
	if !strings.Contains(running, "first online check is running") {
		t.Fatalf("enabled, no check yet: %q", running)
	}
	for name, st := range map[string]fwcatalog.Status{
		"off":           {Online: true},
		"no source":     {Enabled: true},
		"checked, none": {Enabled: true, Online: true, LastCheck: &store.CatalogCheckRow{Result: "download", At: now}},
	} {
		if line, _ := catalogLine(st, timeFmt{loc: time.UTC}, now); !strings.HasPrefix(line, "No vendor catalog is imported") {
			t.Errorf("%s: %q", name, line)
		}
	}
}

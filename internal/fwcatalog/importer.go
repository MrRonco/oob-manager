// Package fwcatalog fetches and imports vendor firmware catalogs for the read-only
// update check (docs/plans/08-update-checker.md). A catalog arrives online (opt-in), as
// an admin upload or from the CLI; every path runs the same pipeline: bounded staging,
// the detached signature check BEFORE anything is decompressed, a bounded streaming
// parse, the shrink hold, then the verified file is cached next to the database so a
// fleet change can be re-parsed with no network. Nothing here fetches a firmware
// package or talks to a BMC (CLAUDE.md rule 11).
package fwcatalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/bmc/textclean"
	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/store"
)

// Origins of an import (catalog_imports.origin).
const (
	OriginOnline = "online"
	OriginUpload = "upload"
	OriginCLI    = "cli"
)

// MaxCatalogBytes caps a catalog file, compressed (Dell's is 1.5 MiB).
const MaxCatalogBytes = 16 << 20

// ErrUnsigned refuses a catalog without a signature (the online fetch always; an upload
// or CLI import unless firmware.catalog.allow_unsigned is set).
var ErrUnsigned = fmt.Errorf("%w: the catalog has no signature", catalog.ErrSignature)

// Importer runs the import pipeline for one source.
type Importer struct {
	Source catalog.UpdateSource
	Repo   store.CatalogRepository
	// Dir caches the verified files (<data>/catalog/<source>, created 0700).
	Dir    string
	Limits catalog.Limits
	// AllowUnsigned accepts an unsigned upload or CLI import (never an online one).
	AllowUnsigned bool
	// Want returns the fleet's systems (nil: none, so nothing is kept).
	Want func(ctx context.Context) (catalog.Want, error)
	Now  func() time.Time
	// Audit records firmware.catalog.imported / .failed (nil: not audited).
	Audit func(ctx context.Context, e audit.Entry)
}

// Input is one catalog to import.
type Input struct {
	Origin string
	// File holds the compressed catalog (from Stage). It is moved into the cache on
	// success and removed otherwise.
	File               string
	Sig                []byte // empty: unsigned
	ETag, LastModified string
	By                 string // the principal ("system" for the scheduler)
	AuthMethod         string // the principal's method ("system", "cli", "session")
	Role, IP           string // the admin's role and address (uploads)
}

// Result describes a stored import.
type Result struct {
	ImportID       int64
	State          string // store.CatalogActive or store.CatalogHeld
	Manifest       catalog.Manifest
	Components     int
	Kept, Previous int // releases kept now, and by the active import before (0: none)
	Signer         catalog.Signer
	SHA256         string
}

func (im Importer) now() time.Time {
	if im.Now != nil {
		return im.Now().UTC()
	}
	return time.Now().UTC()
}

// Stage copies r (at most MaxCatalogBytes) into a new temp file in dir and returns its
// path. More bytes than the cap is ErrSize and leaves nothing behind.
func Stage(dir string, r io.Reader) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("fwcatalog: cache directory: %w", err)
	}
	f, err := os.CreateTemp(dir, "incoming-*.tmp")
	if err != nil {
		return "", fmt.Errorf("fwcatalog: stage: %w", err)
	}
	n, err := io.Copy(f, io.LimitReader(r, MaxCatalogBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		_ = os.Remove(f.Name())
		return "", err
	case n > MaxCatalogBytes:
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("%w: the catalog is larger than %d MiB", catalog.ErrSize, MaxCatalogBytes>>20)
	}
	return f.Name(), nil
}

// Import runs the pipeline on in and records the check. Any failure keeps the previous
// catalog and is returned with its class (catalog.Class).
func (im Importer) Import(ctx context.Context, in Input) (Result, error) {
	res, err := im.importFile(ctx, in)
	if err != nil {
		_ = os.Remove(in.File)
		im.record(ctx, catalog.Class(err), err, 0)
		im.audit(ctx, in, "firmware.catalog.failed", map[string]any{"origin": in.Origin, "class": catalog.Class(err)},
			audit.ResultError, catalog.Class(err))
		return Result{}, err
	}
	im.audit(ctx, in, "firmware.catalog.imported", map[string]any{"origin": in.Origin, "version": res.Manifest.Version,
		"sha256": res.SHA256, "signer": res.Signer.Fingerprint, "kept": res.Kept, "state": res.State}, audit.ResultOK, "")
	result := "imported"
	if res.State == store.CatalogHeld {
		result = "held"
	}
	im.record(ctx, result, nil, res.ImportID)
	return res, nil
}

func (im Importer) importFile(ctx context.Context, in Input) (Result, error) {
	sum, err := fileSHA256(in.File)
	if err != nil {
		return Result{}, err
	}
	signer, err := im.verify(in)
	if err != nil {
		return Result{}, err
	}
	snap, err := im.parse(ctx, in.File)
	if err != nil {
		return Result{}, err
	}
	rels, models := rows(snap)
	res := Result{State: store.CatalogActive, Manifest: snap.Manifest, Components: snap.Components, Kept: len(rels),
		Signer: signer, SHA256: sum}
	prev, ok, perr := im.Repo.Import(ctx, im.Source.Name(), store.CatalogActive)
	if perr != nil {
		return Result{}, perr
	}
	if ok {
		res.Previous = prev.Kept
		if prev.Kept > 0 && 2*len(rels) < prev.Kept {
			res.State = store.CatalogHeld // far fewer rows than the catalog in use (plan §15)
		}
	}
	sig := in.Sig
	if signer.Fingerprint == "" {
		sig = nil // unsigned (accepted by configuration): no .sign is cached
	}
	if err = im.cache(in.File, sig, sum); err != nil {
		return Result{}, err
	}
	res.ImportID, err = im.Repo.SaveImport(ctx, store.CatalogImportRow{
		Source: im.Source.Name(), Origin: in.Origin, State: res.State, Version: snap.Manifest.Version,
		ReleaseID: snap.Manifest.ReleaseID, PublishedAt: snap.Manifest.Published, ImportedAt: im.now(), SHA256: sum,
		Signer: signer.Fingerprint, ETag: clip(in.ETag, 256), LastModified: clip(in.LastModified, 64),
		Components: snap.Components, ImportedBy: by(in.By)}, rels, models)
	if err != nil {
		return Result{}, err
	}
	im.pruneCache(ctx)
	return res, nil
}

// verify checks the signature, or accepts an unsigned upload/CLI import when allowed.
func (im Importer) verify(in Input) (catalog.Signer, error) {
	if len(bytes.TrimSpace(in.Sig)) == 0 {
		if im.AllowUnsigned && in.Origin != OriginOnline {
			return catalog.Signer{}, nil
		}
		return catalog.Signer{}, ErrUnsigned
	}
	f, err := os.Open(in.File)
	if err != nil {
		return catalog.Signer{}, err
	}
	defer f.Close()
	return im.Source.Verify(f, in.Sig)
}

// verifySigned checks a cached file against its cached signature and the signer recorded
// at import.
func (im Importer) verifySigned(path string, sig []byte, signer string) error {
	if len(bytes.TrimSpace(sig)) == 0 {
		return ErrUnsigned
	}
	f, err := os.Open(path) //nolint:gosec // G304: a cached file under the catalog directory
	if err != nil {
		return err
	}
	defer f.Close()
	s, err := im.Source.Verify(f, sig)
	if err != nil {
		return err
	}
	if s.Fingerprint != signer {
		return fmt.Errorf("%w: signed by another key than at import", catalog.ErrSignature)
	}
	return nil
}

func (im Importer) parse(ctx context.Context, path string) (catalog.Snapshot, error) {
	var want catalog.Want
	if im.Want != nil {
		w, err := im.Want(ctx)
		if err != nil {
			return catalog.Snapshot{}, err
		}
		want = w
	}
	f, err := os.Open(path) //nolint:gosec // G304: a staged or cached file under the catalog directory
	if err != nil {
		return catalog.Snapshot{}, err
	}
	defer f.Close()
	return im.Source.Parse(ctx, f, want, im.Limits)
}

// Reparse re-reads the cached files of the active and held imports for the current
// fleet (a server was added or its model changed): no network. A cached file that no
// longer verifies is left alone and reported.
func (im Importer) Reparse(ctx context.Context) error {
	var errs []error
	for _, state := range []string{store.CatalogActive, store.CatalogHeld} {
		imp, ok, err := im.Repo.Import(ctx, im.Source.Name(), state)
		if err != nil || !ok {
			errs = append(errs, err)
			continue
		}
		path := filepath.Join(im.Dir, imp.SHA256+".xml.gz")
		sig, _ := os.ReadFile(path + ".sign") //nolint:gosec // G304: a path under the cache directory, named by a hex digest
		if imp.Signer != "" {
			// A signed import stays signed: its cached signature must verify, by the same key.
			if verr := im.verifySigned(path, sig, imp.Signer); verr != nil {
				errs = append(errs, fmt.Errorf("fwcatalog: cached catalog %s: %w", imp.Version, verr))
				continue
			}
		}
		snap, err := im.parse(ctx, path)
		if err != nil {
			errs = append(errs, fmt.Errorf("fwcatalog: cached catalog %s: %w", imp.Version, err))
			continue
		}
		rels, models := rows(snap)
		errs = append(errs, im.Repo.ReplaceReleases(ctx, imp.ID, rels, models))
	}
	return errors.Join(errs...)
}

// cache moves the verified file to <dir>/<sha256>.xml.gz and writes its signature next
// to it (mode 0600).
func (im Importer) cache(path string, sig []byte, sum string) error {
	dst := filepath.Join(im.Dir, sum+".xml.gz")
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	if err := os.Rename(path, dst); err != nil {
		return fmt.Errorf("fwcatalog: cache: %w", err)
	}
	if len(sig) == 0 {
		_ = os.Remove(dst + ".sign")
		return nil
	}
	return os.WriteFile(dst+".sign", sig, 0o600)
}

// pruneCache removes cached files that belong to neither the active nor the held import.
func (im Importer) pruneCache(ctx context.Context) {
	keep := map[string]bool{}
	for _, state := range []string{store.CatalogActive, store.CatalogHeld} {
		if imp, ok, err := im.Repo.Import(ctx, im.Source.Name(), state); err == nil && ok {
			keep[imp.SHA256+".xml.gz"], keep[imp.SHA256+".xml.gz.sign"] = true, true
		}
	}
	entries, err := os.ReadDir(im.Dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !keep[e.Name()] && !strings.HasPrefix(e.Name(), "incoming-") {
			_ = os.Remove(filepath.Join(im.Dir, e.Name()))
		}
	}
}

// record stores a check row; a failure's detail is the error text (ours, never a
// response body), cleaned and capped.
func (im Importer) record(ctx context.Context, result string, err error, importID int64) {
	detail := ""
	if err != nil {
		detail = textclean.Clean(err.Error(), 256)
	}
	_ = im.Repo.AddCheck(ctx, store.CatalogCheckRow{Source: im.Source.Name(), At: im.now(), Result: result,
		Detail: detail, ImportID: importID})
}

func (im Importer) audit(ctx context.Context, in Input, action string, params map[string]any, result, class string) {
	if im.Audit == nil {
		return
	}
	method := in.AuthMethod
	if method == "" {
		method = "system"
	}
	im.Audit(ctx, audit.Entry{Principal: by(in.By), AuthMethod: method, Role: in.Role, SrcIP: in.IP, Action: action,
		Params: params, Result: result, ErrorClass: class})
}

// Record stores a check that did not reach the pipeline (not_modified, a download
// failure, disabled).
func (im Importer) Record(ctx context.Context, result string, err error) {
	im.record(ctx, result, err, 0)
}

func rows(snap catalog.Snapshot) ([]store.CatalogReleaseRow, []store.CatalogModelRow) {
	rels := make([]store.CatalogReleaseRow, 0, len(snap.Entries))
	for _, e := range snap.Entries {
		rels = append(rels, store.CatalogReleaseRow{SystemID: e.SystemID, ComponentID: e.ComponentID,
			VendorID: e.VendorID, DeviceID: e.DeviceID, SubVendorID: e.SubVendorID, SubDeviceID: e.SubDeviceID,
			Version: e.Version, ReleasedAt: e.Date, Criticality: int(e.Criticality), Name: e.Name,
			PackagePath: e.PackagePath, DetailsURL: e.DetailsURL, RebootRequired: e.RebootRequired})
	}
	var models []store.CatalogModelRow
	for id, names := range snap.Models {
		for _, n := range names {
			if n != "" {
				models = append(models, store.CatalogModelRow{SystemID: id, Model: n})
			}
		}
	}
	return rels, models
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the staged temp file
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func clip(s string, n int) string { return textclean.Clean(s, n) }

func by(s string) string {
	if s == "" {
		return "system"
	}
	return s
}

//go:build dellnet

package fwcatalog

import (
	"context"
	"path/filepath"
	"testing"

	"oob-manager/internal/egress"
	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/firmware/catalog/dell"
	"oob-manager/internal/store"
)

// TestLiveDellCatalog (opt-in: -tags dellnet; the nightly job runs it, never the blocking
// CI) downloads Dell's real catalog and signature, verifies them against the embedded
// key and checks that the iDRAC9 test system (088F) is listed.
func TestLiveDellCatalog(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	got, err := Fetcher{URL: dell.DefaultURL, UserAgent: "oob-manager/nightly", Policy: egress.Policy{}}.Fetch(ctx, dir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "oob.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	src, err := dell.NewSource(nil)
	if err != nil {
		t.Fatal(err)
	}
	im := Importer{Source: src, Repo: db.Catalog(), Dir: dir, Limits: catalog.DefaultLimits(),
		Want: func(context.Context) (catalog.Want, error) {
			return catalog.Want{SystemIDs: map[string]bool{"088F": true, "0627": true}}, nil
		}}
	res, err := im.Import(ctx, Input{Origin: OriginOnline, File: got.File, Sig: got.Sig, ETag: got.ETag})
	if err != nil {
		t.Fatal(err)
	}
	if res.Signer.Fingerprint != dell.DellFingerprint || res.Kept == 0 || res.Components < 100 {
		t.Fatalf("result %+v", res)
	}
	t.Logf("catalog %s published %s: %d components, %d releases kept for 088F/0627", res.Manifest.Version,
		res.Manifest.Published.Format("2006-01-02"), res.Components, res.Kept)
}

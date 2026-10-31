package fwcatalog

import (
	"context"

	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/store"
)

// ScanLister lists the servers' last firmware scans (store.FirmwareRepository).
type ScanLister interface {
	Scans(ctx context.Context) ([]store.FirmwareScanRow, error)
}

// FleetWant returns the Want of the fleet: every scanned server's system ID, an
// override from firmware.catalog.systems (server ID → system ID) in its place, and the
// model of every server without either (the iDRAC8 fallback, plan 08 §8.1).
func FleetWant(scans ScanLister, overrides map[string]string) func(context.Context) (catalog.Want, error) {
	return func(ctx context.Context) (catalog.Want, error) {
		rows, err := scans.Scans(ctx)
		if err != nil {
			return catalog.Want{}, err
		}
		w := catalog.Want{SystemIDs: map[string]bool{}, Models: map[string]bool{}}
		for _, id := range overrides {
			w.SystemIDs[id] = true
		}
		for _, s := range rows {
			switch {
			case overrides[s.ServerID] != "":
			case s.SystemID != "":
				w.SystemIDs[s.SystemID] = true
			case s.Model != "":
				w.Models[catalog.NormalizeModel(s.Model)] = true
			}
		}
		return w, nil
	}
}

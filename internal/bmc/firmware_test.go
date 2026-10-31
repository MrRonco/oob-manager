package bmc

import (
	"testing"
	"time"
)

func TestParseFirmwareKind(t *testing.T) {
	for _, k := range FirmwareKinds() {
		got, ok := ParseFirmwareKind(string(k))
		if !ok || got != k {
			t.Errorf("ParseFirmwareKind(%q) = %q, %v", k, got, ok)
		}
		if k.Label() == "" || k.Label() == string(k) && k != FirmwareOther {
			t.Errorf("kind %q has no label", k)
		}
	}
	for _, bad := range []string{"", "BMC", "cpu", "bios "} {
		if _, ok := ParseFirmwareKind(bad); ok {
			t.Errorf("ParseFirmwareKind(%q) accepted", bad)
		}
	}
	if FirmwareKind("x").Label() != "x" || FirmwareKind("x").Rank() != len(FirmwareKinds()) {
		t.Error("an unknown kind sorts last and keeps its text")
	}
	if FirmwareBMC.Rank() != 0 || FirmwareOther.Rank() != len(FirmwareKinds())-1 {
		t.Error("kinds rank in display order")
	}
}

func TestFirmwareScanCopies(t *testing.T) {
	items := []FirmwareItem{{ID: "a", Version: "1", ReleaseDate: time.Unix(1, 0)}}
	s := NewFirmwareScan(items, 3, true)
	items[0].Version = "changed"
	got := s.Items()
	if got[0].Version != "1" || s.Listed() != 3 || !s.Complete() {
		t.Fatalf("scan %+v listed %d complete %v", got, s.Listed(), s.Complete())
	}
	got[0].Version = "again"
	if s.Items()[0].Version != "1" {
		t.Fatal("Items must return a copy")
	}
	r := s.WithDocs(2, 1)
	if r.DocsRead() != 2 || r.DocsFailed() != 1 || s.DocsRead() != 0 {
		t.Fatal("WithDocs returns a new value")
	}
	if NewFirmwareScan(nil, -1, false).Listed() != 0 {
		t.Fatal("a negative count is clamped")
	}
}

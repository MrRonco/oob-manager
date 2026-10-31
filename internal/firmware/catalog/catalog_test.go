package catalog

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestNullCatalog(t *testing.T) {
	c := Null()
	m, ok, err := c.Lookup(context.Background(), Key{ComponentID: "159"})
	if ok || err != nil || m != (Match{}) {
		t.Fatalf("Lookup = %+v, %v, %v", m, ok, err)
	}
	info, err := c.Info(context.Background())
	if err != nil || info.Imported() || info.Text() != "Catalog: none imported" {
		t.Fatalf("Info = %+v, %v (%q)", info, err, info.Text())
	}
	full := Info{Name: "Dell catalog", Entries: 12}
	if !full.Imported() || full.Text() != "Catalog: Dell catalog (12 entries)" {
		t.Fatalf("text %q", full.Text())
	}
}

func TestKeyFromIdentity(t *testing.T) {
	k := KeyFromIdentity("DCIM:firmware:14E4:165F:1028:088F", "105897", "08HFV1")
	want := Key{VendorID: "14E4", DeviceID: "165F", SubVendorID: "1028", SubDeviceID: "088F", ComponentID: "105897", SystemID: "08HFV1"}
	if k != want {
		t.Fatalf("key %+v", k)
	}
	if k := KeyFromIdentity("", "159", ""); k != (Key{ComponentID: "159"}) {
		t.Fatalf("iDRAC8 key %+v", k)
	}
	if k := KeyFromIdentity("DCIM:bios:x", "159", ""); k != (Key{ComponentID: "159"}) {
		t.Fatalf("a short identity is ignored: %+v", k)
	}
}

func TestCriticality(t *testing.T) {
	cases := map[Criticality][2]string{
		CriticalityUrgent: {"urgent", "Urgent"}, CriticalityRecommended: {"recommended", "Recommended"},
		CriticalityOptional: {"optional", "Optional"}, CriticalityUnknown: {"", ""}, Criticality(9): {"", ""},
	}
	for c, want := range cases {
		if c.String() != want[0] || c.Label() != want[1] || c.Valid() != (want[0] != "") {
			t.Errorf("%d: %q %q %v", c, c.String(), c.Label(), c.Valid())
		}
	}
	if (Device{ComponentID: "1"}).HasPCI() || !(Device{VendorID: "14E4"}).HasPCI() {
		t.Error("HasPCI")
	}
}

func TestClassAndWant(t *testing.T) {
	cases := map[error]string{nil: "", ErrDownload: "download", ErrSize: "size", ErrSignature: "signature",
		ErrUntrustedKey: "untrusted_key", ErrParse: "parse", fmt.Errorf("wrapped: %w", ErrSize): "size",
		errors.New("anything else"): "download"}
	for err, want := range cases {
		if got := Class(err); got != want {
			t.Errorf("Class(%v) = %q, want %q", err, got, want)
		}
	}
	w := Want{SystemIDs: map[string]bool{"088F": true}, Models: map[string]bool{NormalizeModel(" PowerEdge   r7xx "): true}}
	if !w.Wants("088F", "") || !w.Wants("0001", "POWEREDGE R7XX") || w.Wants("0001", "") || w.Wants("0001", "Other") {
		t.Error("Wants")
	}
	if d := DefaultLimits(); d.MaxDecompressed != 128<<20 || d.MaxDepth != 16 || d.ParseTime <= 0 {
		t.Errorf("limits %+v", d)
	}
}

func TestResolveModel(t *testing.T) {
	s := Snapshot{Models: map[string][]string{"0627": {"PowerEdge R7XX"}, "0A01": {"PowerEdge T1", "PowerEdge T1 "}, "0A02": {"PowerEdge T1"}}}
	if id, ok := s.ResolveModel("poweredge r7xx"); !ok || id != "0627" {
		t.Errorf("unique model: %q %v", id, ok)
	}
	if id, ok := s.ResolveModel("PowerEdge T1"); ok {
		t.Errorf("ambiguous model resolved to %q", id)
	}
	if _, ok := s.ResolveModel("PowerEdge Z9"); ok {
		t.Error("unknown model resolved")
	}
}

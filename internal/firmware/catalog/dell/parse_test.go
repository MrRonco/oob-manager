package dell

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/firmware/catalog/catalogtest"
)

func wantFleet() catalog.Want {
	return catalog.Want{SystemIDs: map[string]bool{catalogtest.SystemIDNew: true},
		Models: map[string]bool{catalog.NormalizeModel(catalogtest.ModelOld): true}}
}

func parse(t *testing.T, gz []byte, lim catalog.Limits) (catalog.Snapshot, error) {
	t.Helper()
	return Parse(context.Background(), bytes.NewReader(gz), wantFleet(), lim)
}

func TestParseSynthetic(t *testing.T) {
	snap, err := parse(t, catalogtest.Catalog(), catalog.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	m := snap.Manifest
	if m.Version != "26.10.22" || m.ReleaseID != "SYN01" || m.BaseLocation != "downloads.example.com" ||
		!m.Published.Equal(time.Date(2026, 10, 22, 9, 9, 35, 0, time.UTC)) {
		t.Errorf("manifest %+v", m)
	}
	// 11 listed + 28 filler; the prerequisite inside <Prerequisites> is not a component.
	if snap.Components != 39 {
		t.Errorf("components %d", snap.Components)
	}
	got := map[string][]string{}
	for _, e := range snap.Entries {
		key := e.SystemID + "/" + e.ComponentID
		got[key] = append(got[key], e.Version+"@"+e.VendorID+e.DeviceID+e.SubVendorID+e.SubDeviceID)
	}
	want := map[string]string{
		"088F/159":    "2.25.2@ 2.21.0@",
		"088F/25227":  "7.00.00.185@",
		"088F/105897": "23.31.6@14E4165F102808FF 23.31.6@14E4165F10280001 24.0.0@14E4163910280002",
		"088F/106864": "E014@",
		"088F/106883": "2.5.13.3025@",
		"0627/25227":  "2.40.40.40@",
	}
	if len(got) != len(want) {
		t.Errorf("kept %v", got)
	}
	for k, v := range want {
		if strings.Join(got[k], " ") != v {
			t.Errorf("%s: %v, want %s", k, got[k], v)
		}
	}
	if _, ok := got["088F/102301"]; ok {
		t.Error("a driver (DRVR) sharing a firmware component ID was kept")
	}
	if id, ok := snap.ResolveModel("POWEREDGE  r730XD"); !ok || id != catalogtest.SystemIDOld {
		t.Errorf("model fallback: %q %v (models %v)", id, ok, snap.Models)
	}
	for _, e := range snap.Entries {
		if e.ComponentID == "25227" && e.SystemID == "088F" {
			r := e.Release
			if r.Criticality != catalog.CriticalityUrgent || r.Name != "iDRAC 7.00.00.185" || !r.RebootRequired ||
				!strings.HasPrefix(r.DetailsURL, "https://www.dell.com/") || r.Date.Format("2006-01-02") != "2026-08-27" {
				t.Errorf("iDRAC release %+v", r)
			}
		}
		if e.ComponentID == "106883" && e.Date.Format("2006-01-02") != "2026-03-03" {
			t.Errorf("releaseDate fallback: %v", e.Date)
		}
	}
}

func TestParseUTF8Catalog(t *testing.T) {
	text := strings.Replace(catalogtest.XML(), `encoding="utf-16"`, `encoding="utf-8"`, 1)
	if _, err := parse(t, catalogtest.Gzip([]byte(text)), catalog.DefaultLimits()); err != nil {
		t.Fatalf("a UTF-8 catalog: %v", err)
	}
	// Without a byte order mark, a utf-16 prolog is a lie: refused.
	if _, err := parse(t, catalogtest.Gzip([]byte(catalogtest.XML())), catalog.DefaultLimits()); !errors.Is(err, catalog.ErrParse) {
		t.Fatalf("utf-16 prolog without a BOM: %v", err)
	}
}

func TestParseBounds(t *testing.T) {
	small := func(f func(*catalog.Limits)) catalog.Limits {
		l := catalog.DefaultLimits()
		f(&l)
		return l
	}
	doc := func(inner string) []byte {
		return catalogtest.Encode(`<?xml version="1.0" encoding="utf-16"?><Manifest version="1">` + inner + `</Manifest>`)
	}
	cases := []struct {
		name  string
		gz    []byte
		lim   catalog.Limits
		class error
	}{
		{"decompressed size", catalogtest.Catalog(), small(func(l *catalog.Limits) { l.MaxDecompressed = 4096 }), catalog.ErrSize},
		{"gzip bomb", catalogtest.Gzip(append([]byte("<Manifest>"), bytes.Repeat([]byte(" "), 8<<20)...)),
			small(func(l *catalog.Limits) { l.MaxDecompressed, l.MaxText = 1<<20, 1<<30 }), catalog.ErrSize},
		{"two gzip members", append(catalogtest.Catalog(), catalogtest.Catalog()...), catalog.DefaultLimits(), catalog.ErrParse},
		{"not gzip", []byte("<Manifest/>"), catalog.DefaultLimits(), catalog.ErrParse},
		{"depth", doc(strings.Repeat("<a>", 20) + strings.Repeat("</a>", 20)), catalog.DefaultLimits(), catalog.ErrParse},
		{"attribute", doc(`<a x="` + strings.Repeat("y", 5000) + `"/>`), catalog.DefaultLimits(), catalog.ErrSize},
		{"text node", doc(`<a>` + strings.Repeat("y", 70000) + `</a>`), catalog.DefaultLimits(), catalog.ErrSize},
		{"token before buffering", doc(`<a>` + strings.Repeat("y", maxTokenGap+1) + `</a>`),
			small(func(l *catalog.Limits) { l.MaxText = 1 << 30 }), catalog.ErrSize},
		{"doctype with an entity", catalogtest.Encode(`<?xml version="1.0" encoding="utf-16"?><!DOCTYPE m [<!ENTITY x "y">]><Manifest/>`), catalog.DefaultLimits(), catalog.ErrParse},
		{"undeclared entity", doc(`<a>&x;</a>`), catalog.DefaultLimits(), catalog.ErrParse},
		{"component count", catalogtest.Catalog(), small(func(l *catalog.Limits) { l.MaxComponents = 5 }), catalog.ErrSize},
		{"devices", catalogtest.Catalog(), small(func(l *catalog.Limits) { l.MaxPCI = 1 }), catalog.ErrSize},
		{"entries", catalogtest.Catalog(), small(func(l *catalog.Limits) { l.MaxEntries = 3 }), catalog.ErrSize},
		{"wrong root", catalogtest.Encode(`<?xml version="1.0" encoding="utf-16"?><Other/>`), catalog.DefaultLimits(), catalog.ErrParse},
		{"truncated", catalogtest.Encode(`<?xml version="1.0" encoding="utf-16"?><Manifest><a>`), catalog.DefaultLimits(), catalog.ErrParse},
		{"two roots", catalogtest.Encode(`<?xml version="1.0" encoding="utf-16"?><Manifest/><Manifest/>`), catalog.DefaultLimits(), catalog.ErrParse},
		{"odd UTF-16", catalogtest.Gzip([]byte{0xFF, 0xFE, '<', 0, 'M'}), catalog.DefaultLimits(), catalog.ErrParse},
		{"other encoding", catalogtest.Gzip([]byte(`<?xml version="1.0" encoding="latin1"?><Manifest/>`)), catalog.DefaultLimits(), catalog.ErrParse},
	}
	for _, c := range cases {
		_, err := parse(t, c.gz, c.lim)
		if !errors.Is(err, c.class) {
			t.Errorf("%s: %v, want %v", c.name, err, c.class)
		}
	}
	devLim := small(func(l *catalog.Limits) { l.MaxDevices = 0 })
	if _, err := parse(t, catalogtest.Catalog(), devLim); !errors.Is(err, catalog.ErrSize) {
		t.Errorf("devices per component: %v", err)
	}
	modelLim := small(func(l *catalog.Limits) { l.MaxModels = 1 })
	if _, err := parse(t, catalogtest.Catalog(), modelLim); !errors.Is(err, catalog.ErrSize) {
		t.Errorf("models per component: %v", err)
	}
}

// slowReader returns one byte at a time with a delay, to hit the parse time limit.
type slowReader struct{ r io.Reader }

func (s slowReader) Read(p []byte) (int, error) {
	time.Sleep(2 * time.Millisecond)
	return s.r.Read(p[:1])
}

func TestParseTimeLimit(t *testing.T) {
	lim := catalog.DefaultLimits()
	lim.ParseTime = 50 * time.Millisecond
	_, err := Parse(context.Background(), slowReader{bytes.NewReader(catalogtest.Catalog())}, wantFleet(), lim)
	if !errors.Is(err, catalog.ErrParse) {
		t.Fatalf("slow input: %v", err)
	}
}

func TestParseInvalidIdentifiersAreSkipped(t *testing.T) {
	text := strings.Replace(catalogtest.XML(), `systemID="0627"`, `systemID="06 27"`, 1)
	text = strings.Replace(text, `systemID="0890"`, `systemID="08-90"`, 1) // beside a valid 088F model
	snap, err := parse(t, catalogtest.Encode(text), catalog.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	bios := 0
	for _, e := range snap.Entries {
		if e.SystemID == catalogtest.SystemIDOld {
			t.Fatalf("a component with an invalid system ID was kept: %+v", e)
		}
		if e.ComponentID == "159" && e.Version == "2.25.2" {
			bios++
		}
	}
	if bios != 1 {
		t.Fatalf("a malformed model dropped the valid one beside it: %d", bios)
	}
}

func FuzzParseCatalog(f *testing.F) {
	f.Add(catalogtest.Catalog())
	f.Add(catalogtest.Gzip([]byte(`<Manifest><SoftwareComponent/></Manifest>`)))
	lim := catalog.DefaultLimits()
	lim.MaxDecompressed = 1 << 20
	lim.ParseTime = 2 * time.Second
	f.Fuzz(func(t *testing.T, gz []byte) {
		snap, err := Parse(context.Background(), bytes.NewReader(gz), wantFleet(), lim)
		if err != nil {
			if catalog.Class(err) == "download" {
				t.Fatalf("a parse error without a class: %v", err)
			}
			return
		}
		for _, e := range snap.Entries {
			if !e.Criticality.Valid() || e.Version == "" || e.ComponentID == "" {
				t.Fatalf("an invalid entry was kept: %+v", e)
			}
		}
	})
}

func TestSourceAndSystemID(t *testing.T) {
	key := catalogtest.RSAKey(t)
	src, err := NewSource(key.PublicArmored(t))
	if err != nil || src.Name() != "dell" || src.DefaultURL() != DefaultURL {
		t.Fatalf("source %v %v", src.Name(), err)
	}
	data := catalogtest.Catalog()
	if _, err = src.Verify(bytes.NewReader(data), key.Sign(t, data)); err != nil {
		t.Fatal(err)
	}
	snap, err := src.Parse(context.Background(), bytes.NewReader(data), wantFleet(), catalog.DefaultLimits())
	if err != nil || len(snap.Entries) == 0 {
		t.Fatalf("parse: %d entries, %v", len(snap.Entries), err)
	}
	if _, err := NewSource([]byte("junk")); err == nil {
		t.Error("junk extra keys accepted")
	}
	for n, want := range map[int]string{2191: "088F", 1575: "0627", 0: "", -1: "", 0x10000: ""} {
		if got := SystemID(n); got != want {
			t.Errorf("SystemID(%d) = %q, want %q", n, got, want)
		}
	}
}

package history

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/csvx"
	"oob-manager/internal/store"
)

func readCSV(t *testing.T, b []byte) [][]string {
	t.Helper()
	recs, err := csv.NewReader(bytes.NewReader(b)).ReadAll()
	if err != nil {
		t.Fatalf("CSV does not parse: %v\n%s", err, b)
	}
	return recs
}

func TestExportBucketedMatchesTheChart(t *testing.T) {
	end := base.Add(day)
	f := newFixture(t, end)
	f.seed(t, "r1", base, end, 5*time.Minute)
	ctx := context.Background()
	k := f.key(t, "r1", "temp:cpu1")
	p := PlanFor(Range24h, end)
	prep, err := f.svc.PrepareExport(ctx, Export{ServerID: "r1", Keys: []store.SensorKey{k}, Plan: p})
	if err != nil || prep.Rows() != 144 {
		t.Fatalf("prepare = %d rows, %v", prep.Rows(), err)
	}
	var buf bytes.Buffer
	flushes := 0
	if err = f.svc.WriteCSV(ctx, &buf, func() { flushes++ }, prep); err != nil {
		t.Fatal(err)
	}
	recs := readCSV(t, buf.Bytes())
	if strings.Join(recs[0], ",") != strings.Join(BucketHeader(), ",") || len(recs) != 145 {
		t.Fatalf("header %v, %d records", recs[0], len(recs))
	}
	first := recs[1]
	if first[0] != "2026-10-20T00:00:00Z" || first[1] != "2026-10-20T00:10:00Z" || first[2] != "r1" ||
		first[3] != "temp:cpu1" || first[4] != "CPU1 Temp" || first[5] != "temp" || first[6] != "celsius" ||
		first[7] != "0" || first[8] != "2.5" || first[9] != "5" || first[10] != "2" {
		t.Errorf("first row = %v", first)
	}
	sr, _ := f.svc.Series(ctx, k, p)
	if want := csvx.Number(sr.Buckets[3].Avg); recs[4][8] != want {
		t.Errorf("CSV avg %s, chart avg %s", recs[4][8], want)
	}
	if !strings.HasSuffix(buf.String(), "\r\n") || flushes != 0 {
		t.Errorf("CRLF ends, %d flushes for 144 rows", flushes)
	}
}

func TestExportRawAllSensors(t *testing.T) {
	end := base.Add(9 * time.Hour)
	f := newFixture(t, end)
	n := f.seed(t, "r1", base, end, time.Minute) // 1080 rows: one flush
	ctx := context.Background()
	keys, _ := f.svc.Sensors(ctx, "r1")
	p := PlanFor(Range24h, end)
	prep, err := f.svc.PrepareExport(ctx, Export{ServerID: "r1", Keys: keys, Plan: p, Raw: true})
	if err != nil || prep.Rows() != int64(2*n) {
		t.Fatalf("prepare = %d rows, %v; want %d", prep.Rows(), err, 2*n)
	}
	var buf bytes.Buffer
	flushes := 0
	if err = f.svc.WriteCSV(ctx, &buf, func() { flushes++ }, prep); err != nil {
		t.Fatal(err)
	}
	recs := readCSV(t, buf.Bytes())
	if len(recs) != 2*n+1 || strings.Join(recs[0], ",") != strings.Join(RawHeader(), ",") || flushes != 1 {
		t.Fatalf("%d records, header %v, %d flushes", len(recs), recs[0], flushes)
	}
	if r := recs[1]; r[0] != "2026-10-20T00:00:00Z" || r[2] != "temp:cpu1" || r[6] != "0" {
		t.Errorf("first raw row = %v", r)
	}
}

func TestExportLimits(t *testing.T) {
	end := base.Add(2 * time.Hour)
	f := newFixture(t, end)
	f.seed(t, "r1", base, end, time.Minute)
	ctx := context.Background()
	keys, _ := f.svc.Sensors(ctx, "r1")
	f.svc.cfg.MaxExportRows = 20
	if _, err := f.svc.PrepareExport(ctx, Export{ServerID: "r1", Keys: keys, Plan: PlanFor(Range24h, end), Raw: true}); !errors.Is(err, ErrTooManyRows) {
		t.Errorf("raw over the cap: %v", err)
	}
	if _, err := f.svc.PrepareExport(ctx, Export{ServerID: "r1", Keys: keys, Plan: PlanFor(Range24h, end)}); !errors.Is(err, ErrTooManyRows) {
		t.Errorf("bucketed over the cap (2 × 12 buckets with data): %v", err)
	}
	if _, err := f.svc.PrepareExport(ctx, Export{ServerID: "r1", Keys: keys, Plan: PlanFor(Range1y, end), Raw: true}); !errors.Is(err, ErrRawSpan) {
		t.Errorf("raw over a year: %v", err)
	}
	f.svc.cfg.MaxExportRows = MaxExportRows
	prep, err := f.svc.PrepareExport(ctx, Export{ServerID: "r1", Keys: keys, Plan: PlanFor(Range24h, end), Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	flushes := 0
	f.svc.cfg.MaxExportRows = MaxExportRows
	var buf bytes.Buffer
	if err = f.svc.WriteCSV(ctx, &buf, func() { flushes++ }, prep); err != nil || flushes != 0 {
		t.Fatalf("write: %v, %d flushes (240 rows)", err, flushes)
	}
}

func TestExportName(t *testing.T) {
	at := time.Date(2026, 10, 23, 14, 5, 0, 0, time.UTC)
	if got := ExportName("r730xd", "temp:iDRAC.Embedded.1#CPU1Temp", PlanFor(Range7d, at), false, at); got !=
		"r730xd_temp-iDRAC.Embedded.1-CPU1Temp_7d_20261023T1405Z.csv" {
		t.Errorf("name = %s", got)
	}
	if got := ExportName("r240", "", Plan{}, true, at); got != "r240_all-sensors_custom_raw_20261023T1405Z.csv" {
		t.Errorf("name = %s", got)
	}
}

// TestExportSizeIsFixedBeforeWriting: "every sensor" is refused by its upper bound
// (sensors × points) before any series is read, and a raw export streams exactly the
// window it counted, whatever polls arrive meanwhile.
func TestExportSizeIsFixedBeforeWriting(t *testing.T) {
	end := base.Add(2 * time.Hour)
	f := newFixture(t, end)
	f.seed(t, "r1", base, end, time.Minute)
	ctx := context.Background()
	many := make([]store.SensorKey, 300)
	for i := range many {
		many[i] = store.SensorKey{ID: int64(10_000 + i)}
	}
	if _, err := f.svc.PrepareExport(ctx, Export{ServerID: "r1", Keys: many, Plan: PlanFor(Range1y, end)}); !errors.Is(err, ErrTooManyRows) {
		t.Fatalf("300 sensors × 365 days: %v", err)
	}
	keys, _ := f.svc.Sensors(ctx, "r1")
	prep, err := f.svc.PrepareExport(ctx, Export{ServerID: "r1", Keys: keys[:1], Plan: PlanFor(Range24h, end), Raw: true})
	if err != nil || prep.Rows() != 120 {
		t.Fatalf("prepare = %d, %v", prep.Rows(), err)
	}
	f.seed(t, "r1", end, end.Add(3*time.Minute), time.Minute) // polls arrive while it streams
	var buf bytes.Buffer
	if err = f.svc.WriteCSV(ctx, &buf, func() {}, prep); err != nil {
		t.Fatal(err)
	}
	if recs := readCSV(t, buf.Bytes()); len(recs) != 121 {
		t.Fatalf("%d records, want the 120 counted", len(recs)-1)
	}
}

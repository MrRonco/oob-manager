package history

import (
	"context"
	"errors"
	"io"
	"strconv"
	"time"

	"oob-manager/internal/csvx"
	"oob-manager/internal/store"
)

// Export limits (plan §8).
const (
	// MaxExportRows caps one export; a larger one is refused before anything is written
	// (413), so a download is never cut short by the cap.
	MaxExportRows = 100_000
	// MaxExportBytes is csvx's safety net: 100 000 rows of the longest names fit.
	MaxExportBytes = 64 << 20
	// MaxRawSpan is the longest raw (unbucketed) export: the longest raw retention.
	MaxRawSpan = 31 * day
	// exportFlushEvery streams the response every so many rows.
	exportFlushEvery = 1000
)

// Errors of an export.
var (
	ErrTooManyRows = errors.New("history: too many rows for one export")
	ErrRawSpan     = errors.New("history: a raw export covers at most 31 days")
)

// BucketHeader is the bucketed CSV's header: min, avg, max and the sample count per
// bucket (a fresh slice).
func BucketHeader() []string {
	return []string{"bucket_start_utc", "bucket_end_utc", "server", "sensor", "name", "kind", "unit",
		"min", "avg", "max", "samples"}
}

// RawHeader is the raw CSV's header: every stored sample (a fresh slice).
func RawHeader() []string {
	return []string{"timestamp_utc", "server", "sensor", "name", "kind", "unit", "value"}
}

// Export is one CSV export: some sensors of a server over a plan, bucketed like the
// chart or, with Raw, every stored sample.
type Export struct {
	ServerID string
	Keys     []store.SensorKey
	Plan     Plan
	Raw      bool
}

// PreparedExport is an export whose size is known and within the caps.
type PreparedExport struct {
	e        Export
	series   []Series // bucketed exports: read once, written by WriteCSV
	rows     int64
	from, to time.Time // raw exports: the window counted, fixed at preparation
}

// Rows is the number of data rows the export will write.
func (p PreparedExport) Rows() int64 { return p.rows }

// PrepareExport sizes an export before anything is written: a bucketed one first by its
// upper bound (sensors × points, so "every sensor" is refused before it is read into
// memory), then by reading its series; a raw one by counting its samples up to now (the
// window the stream then reads, so later polls do not change it). It refuses one over
// the row cap (ErrTooManyRows) and a raw one longer than MaxRawSpan (ErrRawSpan).
func (s *Service) PrepareExport(ctx context.Context, e Export) (PreparedExport, error) {
	if !e.Raw {
		return s.prepareBuckets(ctx, e)
	}
	from, to := e.Plan.rawWindow()
	if to.Sub(from) > MaxRawSpan {
		return PreparedExport{}, ErrRawSpan
	}
	p := PreparedExport{e: e, from: from, to: minTime(to, s.cfg.Now())}
	for _, k := range e.Keys {
		n, err := s.cfg.Reader.CountRaw(ctx, k.ID, p.from, p.to)
		if err != nil {
			return PreparedExport{}, err
		}
		if p.rows += n; s.checkRows(p.rows) != nil {
			return PreparedExport{}, ErrTooManyRows
		}
	}
	return p, nil
}

func (s *Service) prepareBuckets(ctx context.Context, e Export) (PreparedExport, error) {
	if err := s.checkRows(int64(len(e.Keys)) * int64(e.Plan.Points())); err != nil {
		return PreparedExport{}, err
	}
	series, err := s.Chart(ctx, e.Keys, e.Plan)
	if err != nil {
		return PreparedExport{}, err
	}
	p := PreparedExport{e: e, series: series}
	for _, sr := range series {
		p.rows += int64(len(sr.Buckets))
	}
	return p, nil
}

func (s *Service) checkRows(n int64) error {
	if n > s.cfg.MaxExportRows {
		return ErrTooManyRows
	}
	return nil
}

// WriteCSV streams a prepared export to w (RFC 4180, CRLF, guarded cells), calling
// flush every 1000 rows. Raw samples are read in pages from the read-only connection.
// The writer allows exactly the prepared rows (a raw window could only gain a sample
// already in flight at preparation: two per sensor); an error after the first byte
// means a cut file, which the handler must turn into an aborted response.
func (s *Service) WriteCSV(ctx context.Context, w io.Writer, flush func(), p PreparedExport) error {
	limit := p.rows
	if p.e.Raw {
		limit = min(p.rows+2*int64(len(p.e.Keys)), s.cfg.MaxExportRows)
	}
	cw := csvx.NewWriter(w, csvx.Options{MaxRows: int(max(limit, 1)), MaxBytes: MaxExportBytes,
		FlushEvery: exportFlushEvery, Flush: flush})
	var err error
	if p.e.Raw {
		err = s.writeRaw(ctx, cw, p)
	} else {
		err = writeBuckets(cw, p.e, p.series)
	}
	return errors.Join(err, cw.Close())
}

func cellsOf(serverID string, k store.SensorKey) []string {
	return []string{serverID, k.Key, k.Name, string(k.Kind), string(k.Unit)}
}

func writeBuckets(cw *csvx.Writer, e Export, series []Series) error {
	if err := cw.Header(BucketHeader()...); err != nil {
		return err
	}
	for _, sr := range series {
		id := cellsOf(e.ServerID, sr.Key)
		for _, b := range sr.Buckets {
			row := append([]string{csvx.Time(b.Start), csvx.Time(sr.BucketEnd(b, e.Plan))}, id...)
			row = append(row, csvx.Number(b.Min), csvx.Number(b.Avg), csvx.Number(b.Max), strconv.FormatInt(b.N, 10))
			if err := cw.Row(row...); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) writeRaw(ctx context.Context, cw *csvx.Writer, p PreparedExport) error {
	if err := cw.Header(RawHeader()...); err != nil {
		return err
	}
	for _, k := range p.e.Keys {
		id := cellsOf(p.e.ServerID, k)
		var after time.Time
		for {
			page, err := s.cfg.Reader.Raw(ctx, k.ID, p.from, p.to, after, store.MaxRawPage)
			if err != nil {
				return err
			}
			for _, pt := range page {
				if rerr := cw.Row(append(append([]string{csvx.Time(pt.TS)}, id...), csvx.Number(pt.Value))...); rerr != nil {
					return rerr
				}
			}
			if len(page) < store.MaxRawPage {
				break
			}
			after = page[len(page)-1].TS
		}
	}
	return nil
}

// ExportName is the attachment's file name:
// <server>_<sensor key slug, or all-sensors>_<range or custom>[_raw]_<yyyymmddThhmmZ>.csv.
func ExportName(serverID, sensorKey string, p Plan, raw bool, at time.Time) string {
	scope := "all-sensors"
	if sensorKey != "" {
		scope = csvx.Slug(sensorKey)
	}
	r := string(p.Range)
	if r == "" {
		r = "custom"
	}
	if raw {
		r += "_raw"
	}
	return csvx.Slug(serverID) + "_" + scope + "_" + r + "_" + csvx.Stamp(at) + ".csv"
}

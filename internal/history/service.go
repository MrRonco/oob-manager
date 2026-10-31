package history

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"oob-manager/internal/store"
)

// Retention is how long each tier is kept, in days (Settings → General).
type Retention struct {
	RawDays, HourlyDays, DailyDays int
}

// Config wires a Service.
type Config struct {
	// Writer is the history on the writer connection: the janitor's rollups and prunes.
	Writer store.HistoryRepository
	// Reader and Audit are on the read-only connection (store.OpenReadOnly): charts,
	// exports and the event overlay never hold the writer.
	Reader store.HistoryReader
	Audit  store.AuditSearcher
	// Retention is read at every janitor pass (the settings apply at the next prune).
	Retention func() Retention
	Now       func() time.Time
	Logger    *slog.Logger
	// After waits between janitor passes (default time.After; a test hook).
	After func(time.Duration) <-chan time.Time
	// MaxExportRows caps one export (default MaxExportRows; a test hook).
	MaxExportRows int64
	// Elapsed is the monotonic time since the service started (default: the process's
	// monotonic clock; a test hook): with it the janitor tells a wall clock step from
	// real time passing.
	Elapsed func() time.Duration
	// Boot is the kernel boot ID and uptime (default ReadBoot; false where /proc is not
	// available). A test hook.
	Boot func() (store.BootMark, bool)
}

// Service reads the history for the UI and the API and maintains it.
type Service struct {
	cfg    Config
	status atomic.Pointer[Status]
	// mu serialises the janitor's writes (RunOnce and SyncServers); reads never take it.
	// passed, lastWall and lastMono are this process's last pass (under mu).
	mu       sync.Mutex
	passed   bool
	lastWall time.Time
	lastMono time.Duration
}

// New validates cfg.
func New(cfg Config) (*Service, error) {
	if cfg.Writer == nil || cfg.Reader == nil || cfg.Audit == nil || cfg.Retention == nil {
		return nil, errors.New("history: writer, reader, audit search and retention are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.After == nil {
		cfg.After = time.After
	}
	if cfg.MaxExportRows <= 0 {
		cfg.MaxExportRows = MaxExportRows
	}
	if cfg.Boot == nil {
		cfg.Boot = ReadBoot
	}
	if cfg.Elapsed == nil {
		start := time.Now()
		cfg.Elapsed = func() time.Duration { return time.Since(start) }
	}
	s := &Service{cfg: cfg}
	s.status.Store(&Status{})
	return s, nil
}

// Now is the service's clock (handlers build plans with it).
func (s *Service) Now() time.Time { return s.cfg.Now() }

// Sensors lists a server's sampled sensors in display order: by kind, then by name.
func (s *Service) Sensors(ctx context.Context, serverID string) ([]store.SensorKey, error) {
	keys, err := s.cfg.Reader.Keys(ctx, serverID)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(keys, compareKeys)
	return keys, nil
}

func compareKeys(a, b store.SensorKey) int {
	kinds := store.SensorKinds()
	return cmp.Or(cmp.Compare(slices.Index(kinds, a.Kind), slices.Index(kinds, b.Kind)),
		cmp.Compare(Label(a), Label(b)), cmp.Compare(a.Key, b.Key))
}

// Label is a sensor's display name: its last name, else its key.
func Label(k store.SensorKey) string { return cmp.Or(k.Name, k.Key) }

// Series is one sensor's buckets for a plan.
type Series struct {
	Key      store.SensorKey
	Buckets  []store.Bucket
	Summary  Summary
	Segments []Segment
}

// Coarse reports the part of the series served by a tier coarser than the plan's: that
// tier and where it ends (false: none). "Hourly averages before <time>".
func (s Series) Coarse(p Plan) (store.Tier, time.Time, bool) {
	pi := tierIndex(p.Tier)
	for i := len(s.Segments) - 1; i >= 0; i-- {
		if seg := s.Segments[i]; tierIndex(seg.Tier) > pi {
			return seg.Tier, seg.To, true
		}
	}
	return "", time.Time{}, false
}

// BucketEnd is where a bucket of the series ends: one plan step after its start, or a
// whole coarser bucket (an hour, a day) when a coarser tier served that part.
func (s Series) BucketEnd(b store.Bucket, p Plan) time.Time {
	width := p.Step
	end := b.Start.Add(p.Step)
	for _, seg := range s.Segments {
		if seg.From.Before(end) && b.Start.Before(seg.To) {
			width = max(width, bucketOf(seg.Tier))
		}
	}
	return b.Start.Add(width)
}

// Series reads one sensor for a plan.
func (s *Service) Series(ctx context.Context, k store.SensorKey, p Plan) (Series, error) {
	meta, err := s.cfg.Reader.Meta(ctx)
	if err != nil {
		return Series{}, err
	}
	return s.series(ctx, k, p, meta)
}

func (s *Service) series(ctx context.Context, k store.SensorKey, p Plan, meta store.HistoryMeta) (Series, error) {
	cov, err := s.coverage(ctx, k.ID, meta)
	if err != nil {
		return Series{}, err
	}
	segs := Segments(p, cov)
	parts := make([][]store.Bucket, 0, len(segs))
	for _, seg := range segs {
		bs, berr := s.cfg.Reader.Buckets(ctx, k.ID, seg.Tier, seg.From, seg.To, p.Step)
		if berr != nil {
			return Series{}, berr
		}
		parts = append(parts, bs)
	}
	bs := Merge(parts...)
	return Series{Key: k, Buckets: bs, Summary: Summarize(bs), Segments: segs}, nil
}

func (s *Service) coverage(ctx context.Context, keyID int64, meta store.HistoryMeta) (map[store.Tier]Coverage, error) {
	out := map[store.Tier]Coverage{}
	for _, t := range tierOrder() {
		first, ok, err := s.cfg.Reader.Earliest(ctx, keyID, t)
		if err != nil {
			return nil, err
		}
		c := Coverage{Has: ok, First: first}
		switch t {
		case store.TierHourly:
			c.Done = meta.HourlyDone
		case store.TierDaily:
			c.Done = meta.DailyDone
		}
		out[t] = c
	}
	return out, nil
}

// Chart reads the given sensors (all of a server's, or a subset) for one plan.
func (s *Service) Chart(ctx context.Context, keys []store.SensorKey, p Plan) ([]Series, error) {
	meta, err := s.cfg.Reader.Meta(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Series, 0, len(keys))
	for _, k := range keys {
		sr, serr := s.series(ctx, k, p, meta)
		if serr != nil {
			return nil, serr
		}
		out = append(out, sr)
	}
	return out, nil
}

// ClockJump is when the sampler last saw the wall clock move back (zero: never).
func (s *Service) ClockJump(ctx context.Context) (time.Time, error) {
	meta, err := s.cfg.Reader.Meta(ctx)
	return meta.LastClockJump, err
}

// overlayLimit is how many audit rows one overlay reads (newest first).
const overlayLimit = 1000

// Overlay is the events of a server over a plan: the given log entries (warning and
// critical) and the audit rows of power actions, fan leases, BMC restarts and
// maintenance windows, read from the read-only connection.
func (s *Service) Overlay(ctx context.Context, serverID string, p Plan, logs []LogEntry) (Markers, error) {
	recs, err := s.cfg.Audit.Search(ctx, store.AuditFilter{ServerID: serverID, Actions: AuditActions(),
		Since: p.From, Limit: overlayLimit})
	if err != nil {
		return Markers{}, err
	}
	marks, spans := FromAudit(recs, p.From, p.To)
	return Collect(spans, FromLogs(logs, p.From, p.To), marks), nil
}

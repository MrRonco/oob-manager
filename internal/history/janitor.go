package history

import (
	"context"
	"errors"
	"slices"
	"time"

	"oob-manager/internal/config"
	"oob-manager/internal/store"
)

// Janitor tuning.
const (
	// PruneBatch is the most rows one DELETE removes: the writer connection is free again
	// between batches, so an audit append waits for one batch at most.
	PruneBatch = 5000
	// RunAt is the janitor's minute past every hour (the hour before is complete).
	RunAt = 2 * time.Minute
	// countRuleFactor bounds raw rows per key at 1.5 × raw_days of polls at the fastest
	// allowed interval (config.PollFloor), so a clock stepped back cannot grow the table
	// without bound while time catches up.
	countRuleFactor = 1.5
)

// Status is the janitor's last pass, for Settings and /metrics (computed once an hour:
// counting rows reads every table).
type Status struct {
	Stats                 store.HistoryStats
	HourlyDone, DailyDone time.Time
	LastClockJump         time.Time
	// Clock is the retention clock of the last pass (clock.go) and LastForwardJump when
	// the janitor last saw the wall clock run ahead of real time (zero: never).
	Clock, LastForwardJump time.Time
	// LastRun is when the last pass finished (zero: none yet); PruneTook how long its
	// prunes took; Err is the class of its failure ("" when it succeeded).
	LastRun   time.Time
	PruneTook time.Duration
	Err       string
}

// Status returns the last pass's status (a copy).
func (s *Service) Status() Status { return *s.status.Load() }

// Run runs a pass at start and then at RunAt past every hour until ctx ends.
func (s *Service) Run(ctx context.Context) {
	for {
		if err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
			s.cfg.Logger.Warn("history: janitor pass failed; retrying next hour", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-s.cfg.After(untilNextRun(s.cfg.Now())):
		}
	}
}

// untilNextRun is the wait until the next HH:02.
func untilNextRun(now time.Time) time.Duration {
	next := now.Truncate(time.Hour).Add(RunAt)
	if !next.After(now) {
		next = next.Add(time.Hour)
	}
	return next.Sub(now)
}

// RunOnce rolls up every complete hour and day since the watermarks (at most the raw
// and hourly retention back, so a long downtime never queues more), then prunes every
// tier per key and deletes idle keys, and refreshes the cached Status. Rollups and
// prunes follow the retention clock (clock.go), never a wall clock that jumped ahead. A
// failure leaves the watermarks where they were: the next pass repeats the work
// (rollups are idempotent).
func (s *Service) RunOnce(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	wall, ret := s.cfg.Now().UTC(), s.cfg.Retention()
	meta, err := s.cfg.Writer.Meta(ctx)
	metaRead := err == nil
	var step clockStep
	var took time.Duration
	if err == nil {
		boot, bootOK := s.cfg.Boot()
		step = s.clockFor(meta, wall, boot, bootOK)
		meta, took, err = s.maintain(ctx, meta, wall, step, ret, boot)
	}
	st := Status{HourlyDone: meta.HourlyDone, DailyDone: meta.DailyDone, LastClockJump: meta.LastClockJump,
		LastForwardJump: meta.LastForwardJump, Clock: step.Clock, LastRun: s.Status().LastRun, PruneTook: took}
	if err == nil {
		// Counting reads every table: on the read-only pool, never holding the writer.
		st.Stats, err = s.cfg.Reader.Stats(ctx)
	}
	if err != nil {
		s.status.Store(failedStatus(st, s.Status(), metaRead, err))
		return err
	}
	st.LastRun = wall
	s.status.Store(&st)
	return nil
}

// clockFor is this pass's retention clock; the monotonic time since the last pass is
// known when this process ran it.
//
// Real time since the last pass comes, in order, from the kernel uptime when the boot is
// the same (it survives a restart of the app, so a crash loop gains nothing), from the
// monotonic clock when this process ran the last pass, else it is unknown (a new boot,
// or no /proc): then the 3-hour allowance applies, once per boot when the boot is known.
func (s *Service) clockFor(meta store.HistoryMeta, wall time.Time, boot store.BootMark, bootOK bool) clockStep {
	if bootOK && meta.Boot.ID == boot.ID && boot.Uptime >= meta.Boot.Uptime {
		return advanceClock(meta.LastPassAt, meta.JanitorClock, wall, boot.Uptime-meta.Boot.Uptime, true)
	}
	known := s.passed && meta.LastPassAt.UnixMilli() == s.lastWall.UnixMilli()
	return advanceClock(meta.LastPassAt, meta.JanitorClock, wall, s.cfg.Elapsed()-s.lastMono, known)
}

// maintain runs the pass by the retention clock: rollups, prunes, the pass record and a
// forward step's note.
func (s *Service) maintain(ctx context.Context, meta store.HistoryMeta, wall time.Time, step clockStep,
	ret Retention, boot store.BootMark) (store.HistoryMeta, time.Duration, error) {
	// Rollups run to the wall clock's hour (idempotent: they only add summaries); only
	// the prunes, which delete, follow the retention clock.
	meta, err := s.rollup(ctx, wall, ret, meta)
	if err != nil {
		return meta, 0, err
	}
	started := time.Now()
	if err = s.prune(ctx, step.Clock, ret); err != nil {
		return meta, 0, err
	}
	took := time.Since(started)
	if step.Jumped {
		s.cfg.Logger.Warn("history: the clock is ahead of real time (a forward step, or a restart after downtime); "+
			"old readings are pruned gradually", "wall", wall, "retention_clock", step.Clock)
		if err = s.cfg.Writer.NoteForwardJump(ctx, wall); err != nil {
			return meta, took, err
		}
		meta.LastForwardJump = wall
	}
	if err = s.cfg.Writer.SetPass(ctx, wall, step.Clock, boot); err != nil {
		return meta, took, err
	}
	s.passed, s.lastWall, s.lastMono = true, wall, s.cfg.Elapsed()
	return meta, took, nil
}

// failedStatus is a failed pass's status: its error class, the previous size and, when
// the watermarks could not even be read, the last known ones.
func failedStatus(st, prev Status, metaRead bool, err error) *Status {
	st.Err = "error"
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		st.Err = "canceled"
	}
	st.Stats = prev.Stats
	if !metaRead {
		st.HourlyDone, st.DailyDone, st.LastClockJump = prev.HourlyDone, prev.DailyDone, prev.LastClockJump
		st.Clock, st.LastForwardJump = prev.Clock, prev.LastForwardJump
	}
	return &st
}

func (s *Service) rollup(ctx context.Context, now time.Time, ret Retention, meta store.HistoryMeta) (store.HistoryMeta, error) {
	lastHour := now.Truncate(time.Hour)
	// A watermark ahead of now means the clock was ahead at an earlier pass and has been
	// corrected: roll up the whole retention again (idempotent), or rollups would stop
	// until real time caught up.
	if meta.HourlyDone.After(lastHour) || meta.DailyDone.After(now.Truncate(day)) {
		meta.HourlyDone, meta.DailyDone = time.UnixMilli(0).UTC(), time.UnixMilli(0).UTC()
	}
	start := maxTime(meta.HourlyDone.Add(-time.Hour), now.Add(-days(ret.RawDays)).Truncate(time.Hour))
	for h := start; h.Before(lastHour); h = h.Add(time.Hour) {
		if _, err := s.cfg.Writer.RollupHourly(ctx, h, h.Add(time.Hour)); err != nil {
			return meta, err
		}
	}
	lastDay := now.Truncate(day)
	dstart := maxTime(meta.DailyDone.Add(-day), now.Add(-days(ret.HourlyDays)).Truncate(day))
	for d := dstart; d.Before(lastDay); d = d.Add(day) {
		if _, err := s.cfg.Writer.RollupDaily(ctx, d, d.Add(day)); err != nil {
			return meta, err
		}
	}
	hourly, daily := lastHour, lastDay
	if err := s.cfg.Writer.SetWatermarks(ctx, hourly, daily); err != nil {
		return meta, err
	}
	meta.HourlyDone, meta.DailyDone = hourly, daily
	return meta, nil
}

func days(n int) time.Duration { return time.Duration(n) * day }

// keepRaw is the count rule's bound per key.
func keepRaw(rawDays int) int {
	return int(countRuleFactor * float64(days(rawDays)/config.PollFloor))
}

func (s *Service) prune(ctx context.Context, now time.Time, ret Retention) error {
	keys, err := s.cfg.Writer.Keys(ctx, "")
	if err != nil {
		return err
	}
	for _, k := range keys {
		if perr := s.pruneKey(ctx, k.ID, now, ret); perr != nil {
			return perr
		}
	}
	_, err = s.cfg.Writer.DeleteIdleKeys(ctx, now.Add(-days(ret.DailyDays)))
	return err
}

func (s *Service) pruneKey(ctx context.Context, id int64, now time.Time, ret Retention) error {
	// Raw rows go by whole hours and hourly rows by whole days, so where a finer tier
	// starts, the coarser one ends on its own bucket boundary (Segments).
	w := s.cfg.Writer
	if _, err := w.PruneBefore(ctx, id, store.TierRaw, now.Add(-days(ret.RawDays)).Truncate(time.Hour), PruneBatch); err != nil {
		return err
	}
	if _, err := w.KeepNewest(ctx, id, keepRaw(ret.RawDays), PruneBatch); err != nil {
		return err
	}
	if _, err := w.PruneBefore(ctx, id, store.TierHourly, now.Add(-days(ret.HourlyDays)).Truncate(day), PruneBatch); err != nil {
		return err
	}
	_, err := w.PruneBefore(ctx, id, store.TierDaily, now.Add(-days(ret.DailyDays)), PruneBatch)
	return err
}

// SyncGrace is how long the history of a server missing from the registry is kept
// after its last sample: a server commented out of config.yaml, a typo in its ID or a
// browser delete undone within it keeps its history.
const SyncGrace = 30 * day

// SyncServers deletes, in batches, the history of servers not in ids (the registry's
// servers, enabled or not: a disabled server keeps its history) whose last sample is
// older than SyncGrace; the janitor's idle-key rule removes anything older still.
func (s *Service) SyncServers(ctx context.Context, ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys, err := s.cfg.Writer.Keys(ctx, "")
	if err != nil {
		return err
	}
	cutoff := s.cfg.Now().Add(-SyncGrace)
	for _, k := range keys {
		if slices.Contains(ids, k.ServerID) || k.Last.After(cutoff) {
			continue
		}
		if derr := s.cfg.Writer.DeleteKey(ctx, k.ID, PruneBatch); derr != nil {
			return derr
		}
	}
	return nil
}

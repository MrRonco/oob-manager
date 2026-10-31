package metrics

import "time"

// HistoryState is the sensor history's size and janitor progress (history.Service's
// cached Status, refreshed once an hour). No per-sensor series: the live sensor
// families already carry the readings; the history store never feeds /metrics.
type HistoryState struct {
	RawRows, HourlyRows, DailyRows int64
	DBBytes, FreelistPages         int64
	HourlyDone, DailyDone          time.Time // rollup watermarks (zero: none yet)
	PruneTook                      time.Duration
	// Ready is false until the janitor's first pass (the families are left out).
	Ready bool
}

func historySpecs() []spec {
	return []spec{
		{"oob_history_rows", "Rows in the sensor history, by tier (raw, hourly, daily), as of the last janitor pass.", Gauge},
		{"oob_history_db_bytes", "Size of the database file (page count times page size), as of the last janitor pass.", Gauge},
		{"oob_history_db_freelist_pages", "Free database pages left by prunes and reused by later inserts.", Gauge},
		{"oob_history_rollup_last_timestamp_seconds", "Rollup watermark by tier (hourly, daily): every bucket before it " +
			"is rolled up, Unix seconds.", Gauge},
		{"oob_history_prune_duration_seconds", "How long the last janitor pass's prunes took.", Gauge},
	}
}

func (c *Collector) collectHistory(b *builder) {
	if c.cfg.History == nil {
		return
	}
	h := c.cfg.History()
	if !h.Ready {
		return
	}
	for _, t := range []struct {
		tier string
		n    int64
	}{{"raw", h.RawRows}, {"hourly", h.HourlyRows}, {"daily", h.DailyRows}} {
		b.add("oob_history_rows", float64(t.n), Label{"tier", t.tier})
	}
	b.add("oob_history_db_bytes", float64(h.DBBytes))
	b.add("oob_history_db_freelist_pages", float64(h.FreelistPages))
	b.add("oob_history_rollup_last_timestamp_seconds", unixOrZero(h.HourlyDone), Label{"tier", "hourly"})
	b.add("oob_history_rollup_last_timestamp_seconds", unixOrZero(h.DailyDone), Label{"tier", "daily"})
	b.add("oob_history_prune_duration_seconds", h.PruneTook.Seconds())
}

func unixOrZero(t time.Time) float64 {
	if t.IsZero() || t.Unix() <= 0 {
		return 0
	}
	return unixSeconds(t)
}

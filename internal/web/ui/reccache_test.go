package ui

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"oob-manager/internal/history"
	"oob-manager/internal/store"
)

func TestRecorderCacheTTLAndBound(t *testing.T) {
	t.Parallel()
	var c recorderCache
	t0 := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	k := recCacheKey{"a", "temp:1", "c", t0}
	if _, ok := c.get(k, t0); ok {
		t.Fatal("empty cache hit")
	}
	c.put(k, recGeo{Line: "M0 0"}, t0)
	if g, ok := c.get(k, t0.Add(30*time.Second)); !ok || g.Line != "M0 0" {
		t.Fatal("fresh entry missed")
	}
	if _, ok := c.get(k, t0.Add(recCacheTTL)); ok {
		t.Error("an entry a minute old must miss")
	}
	if _, ok := c.get(k, t0.Add(-time.Second)); ok {
		t.Error("a clock step back must miss")
	}
	for i := range recCacheMax + 5 {
		c.put(recCacheKey{"s", string(rune('a' + i%26)), "c", t0.Add(time.Duration(i) * time.Hour)}, recGeo{}, t0)
	}
	if n := len(c.m); n > recCacheMax {
		t.Errorf("cache holds %d entries, bound %d", n, recCacheMax)
	}
}

// countingHistory counts Chart reads; fail makes them fail.
type countingHistory struct {
	History
	charts atomic.Int32
	fail   bool
}

func (c *countingHistory) Chart(ctx context.Context, keys []store.SensorKey, p history.Plan) ([]history.Series, error) {
	c.charts.Add(1)
	if c.fail {
		return nil, errors.New("read failed")
	}
	return c.History.Chart(ctx, keys, p)
}

// TestRecorderReadsOnceAndCaches (review M6): one Chart call for the recorder's rows, and
// none on a reload within the cache's minute; a failed read leaves the rows text-only.
func TestRecorderReadsOnceAndCaches(t *testing.T) {
	t.Parallel()
	var ch *countingHistory
	h, c := signedIn(t, func(d *Deps) {
		ch = &countingHistory{History: newHistorySvc(t, d.Now())}
		d.History = ch
	})
	result(c.get("/")).status(t, http.StatusOK).contains(t, `class="rec-svg"`)
	first := ch.charts.Load()
	result(c.get("/")).status(t, http.StatusOK).contains(t, `class="rec-svg"`)
	if first != 1 || ch.charts.Load() != first {
		t.Fatalf("Chart reads: %d on the first Overview, %d after a reload", first, ch.charts.Load())
	}
	h.clock.Advance(2 * time.Minute)
	ch.fail = true
	result(c.get("/")).status(t, http.StatusOK).contains(t, "no readings in the last 24 hours").lacks(t, `class="rec-svg"`)
}

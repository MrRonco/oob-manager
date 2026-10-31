package ui

import (
	"sync"
	"time"
)

// recCacheTTL and recCacheMax bound the recorder cache: an Overview reloaded within a
// minute (auto-refresh, several viewers) reuses each row's drawing instead of reading
// the history again; the plan's start is in the key, so a new 30-minute bucket is a miss.
const (
	recCacheTTL = time.Minute
	recCacheMax = 256
)

type recCacheKey struct {
	server, key, unit string
	from              time.Time
}

type recCacheEntry struct {
	geo recGeo
	at  time.Time
}

// recorderCache maps a row to its drawing for recCacheTTL, at most recCacheMax entries
// (when full, expired entries go first, then everything).
type recorderCache struct {
	mu sync.Mutex
	m  map[recCacheKey]recCacheEntry
}

func (c *recorderCache) get(k recCacheKey, now time.Time) (recGeo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok || now.Sub(e.at) >= recCacheTTL || now.Before(e.at) {
		return recGeo{}, false
	}
	return e.geo, true
}

func (c *recorderCache) put(k recCacheKey, g recGeo, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[recCacheKey]recCacheEntry{}
	}
	if len(c.m) >= recCacheMax {
		for key, e := range c.m {
			if now.Sub(e.at) >= recCacheTTL {
				delete(c.m, key)
			}
		}
		if len(c.m) >= recCacheMax {
			clear(c.m)
		}
	}
	c.m[k] = recCacheEntry{geo: g, at: now}
}

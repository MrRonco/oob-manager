package ui

import (
	"fmt"
	"testing"
	"time"
)

func TestLimiterBurstAndRefill(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newLimiter(RateLimit{Events: 5, Per: time.Minute}, 100, func() time.Time { return now })
	for i := range 5 {
		if ok, _ := l.allow("ip:a"); !ok {
			t.Fatalf("attempt %d denied", i+1)
		}
	}
	ok, wait := l.allow("ip:a")
	if ok {
		t.Fatal("6th attempt within a minute allowed")
	}
	if wait <= 0 || wait > 12*time.Second {
		t.Fatalf("retry-after = %s, want (0, 12s]", wait)
	}
	if ok, _ := l.allow("ip:b"); !ok {
		t.Fatal("other key affected")
	}
	now = now.Add(12 * time.Second)
	if ok, _ := l.allow("ip:a"); !ok {
		t.Fatal("token not refilled after 12s")
	}
	if ok, _ := l.allow("ip:a"); ok {
		t.Fatal("refilled more than one token")
	}
}

func TestLimiterBoundedKeys(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newLimiter(RateLimit{Events: 2, Per: time.Hour}, 10, func() time.Time { return now })
	l.allow("victim")
	l.allow("victim")
	for i := range 50 {
		now = now.Add(time.Millisecond)
		l.allow(fmt.Sprintf("spam-%d", i))
	}
	if n := l.size(); n > 10 {
		t.Fatalf("limiter holds %d keys, cap 10", n)
	}
}

func TestLimiterPrunesFullBuckets(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newLimiter(RateLimit{Events: 1, Per: time.Second}, 3, func() time.Time { return now })
	for i := range 3 {
		l.allow(fmt.Sprintf("k%d", i))
	}
	now = now.Add(time.Minute) // all buckets refilled: safe to forget
	l.allow("new")
	if n := l.size(); n != 1 {
		t.Fatalf("size = %d, want 1 after pruning refilled buckets", n)
	}
}

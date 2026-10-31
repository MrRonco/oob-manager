//go:build !race

package dell

import (
	"bytes"
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/firmware/catalog/catalogtest"
)

// TestParseMemoryIsBounded parses a catalog about the size of Dell's (5,000 components,
// ~20 MiB of XML) and samples the heap: the streaming parse must stay well under the
// container's limit (plan 08 §6.3 target: 32 MiB; Dell's real catalog measured 4.4 MiB).
func TestParseMemoryIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	gz := catalogtest.Large(5000)
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak atomic.Uint64
	done := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			if m.HeapInuse > peak.Load() {
				peak.Store(m.HeapInuse)
			}
			select {
			case <-done:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	snap, err := Parse(context.Background(), bytes.NewReader(gz), wantFleet(), catalog.DefaultLimits())
	close(done)
	<-sampled
	if err != nil || snap.Components != 5011 {
		t.Fatalf("parse: %d components, %v", snap.Components, err)
	}
	grew := float64(peak.Load()-min(peak.Load(), base.HeapInuse)) / (1 << 20)
	if grew > 32 {
		t.Fatalf("heap grew %.1f MiB while parsing (limit 32)", grew)
	}
	t.Logf("heap grew %.1f MiB for %d bytes compressed", grew, len(gz))
}

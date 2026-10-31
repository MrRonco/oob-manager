package audit

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingSink records how many messages it accepted.
type countingSink struct{ n atomic.Int64 }

func (c *countingSink) Enqueue(Message) bool { c.n.Add(1); return true }

func TestSwitchSinkNilDrops(t *testing.T) {
	var w SwitchSink
	if w.Enqueue(Message{Short: "x"}) || w.Dropped() != 1 || w.Current() != nil {
		t.Fatalf("empty switch: dropped %d current %v", w.Dropped(), w.Current())
	}
	a := &countingSink{}
	if old := w.Swap(a); old != nil {
		t.Fatalf("old = %v", old)
	}
	if !w.Enqueue(Message{}) || a.n.Load() != 1 || w.Current() != a {
		t.Fatal("not forwarded")
	}
	if old := w.Swap(nil); old != a {
		t.Fatalf("old = %v", old)
	}
	if w.Enqueue(Message{}) || w.Dropped() != 2 {
		t.Fatalf("dropped %d", w.Dropped())
	}
}

// TestSwitchSinkSwapUnderLoad: two real shippers behind the switch, swapped while 8
// goroutines enqueue. Every message is accounted for exactly once: received by A,
// received by B, or counted as dropped (by the switch or a shipper).
func TestSwitchSinkSwapUnderLoad(t *testing.T) {
	lnA, gotA := listen(t)
	lnB, gotB := listen(t)
	cfgA, cfgB := fastConfig(lnA.Addr().String()), fastConfig(lnB.Addr().String())
	cfgA.QueueSize, cfgB.QueueSize = 4096, 4096
	a, err := NewShipper(cfgA, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewShipper(cfgB, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctxA, stopA := context.WithCancel(context.Background())
	ctxB, stopB := context.WithCancel(context.Background())
	defer stopB()
	doneA := make(chan struct{})
	go func() { a.Run(ctxA); close(doneA) }()
	go b.Run(ctxB)

	var w SwitchSink
	w.Swap(a)
	const workers, each = 8, 200
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range each {
				w.Enqueue(Message{Short: "load", Timestamp: t0})
			}
		})
	}
	time.Sleep(2 * time.Millisecond)
	w.Swap(b)
	stopA() // the old shipper flushes what it holds, then closes
	wg.Wait()
	<-doneA
	const after = 10 // the swap may land after every worker finished: these surely go to B
	for range after {
		w.Enqueue(Message{Short: "after", Timestamp: t0})
	}

	total := int64(workers*each + after)
	var recvA, recvB int64
	deadline := time.After(5 * time.Second)
	for {
		// A frame a worker handed to A after A finished flushing stays in A's queue.
		dropped := int64(w.Dropped()+a.Stats().Dropped+b.Stats().Dropped) + int64(a.Stats().Queued) //nolint:gosec // test counters, far below 2^63
		if recvA+recvB+dropped == total && b.Stats().Queued == 0 {
			break
		}
		select {
		case <-gotA:
			recvA++
		case <-gotB:
			recvB++
		case <-deadline:
			t.Fatalf("accounted %d+%d+%d of %d", recvA, recvB, dropped, total)
		}
	}
	if recvB == 0 {
		t.Fatal("nothing reached the new shipper")
	}
	if a.Stats().Sent != uint64(recvA) || b.Stats().Sent < uint64(recvB) {
		t.Fatalf("sent counters a=%d/%d b=%d/%d", a.Stats().Sent, recvA, b.Stats().Sent, recvB)
	}
}

package audit

import "sync/atomic"

// SwitchSink is a Sink whose target can be replaced at run time (Settings →
// Integrations swaps the GELF shipper without a restart, tech_doc §34). Enqueue loads
// the current target and forwards; with no target the message is dropped and counted.
// The zero value is ready to use and forwards nowhere.
type SwitchSink struct {
	cur     atomic.Pointer[sinkBox]
	dropped atomic.Uint64
}

// sinkBox holds an interface value behind one pointer (atomic.Pointer needs a type).
type sinkBox struct{ s Sink }

// Enqueue implements Sink.
func (w *SwitchSink) Enqueue(m Message) bool {
	if b := w.cur.Load(); b != nil && b.s != nil {
		return b.s.Enqueue(m)
	}
	w.dropped.Add(1)
	return false
}

// Swap installs s (nil: forward nowhere) and returns the previous target.
func (w *SwitchSink) Swap(s Sink) Sink {
	old := w.cur.Swap(&sinkBox{s: s})
	if old == nil {
		return nil
	}
	return old.s
}

// Current returns the installed target (nil when none).
func (w *SwitchSink) Current() Sink {
	if b := w.cur.Load(); b != nil {
		return b.s
	}
	return nil
}

// Dropped counts messages that arrived while no target was installed.
func (w *SwitchSink) Dropped() uint64 { return w.dropped.Load() }

package integrations

import "oob-manager/internal/audit"

// shipState is what Stats reads, published in one atomic store so a scrape never sees a
// half-done swap: the current shipper, the replaced ones still flushing (read live, so
// what they send or drop after the swap still counts) and the totals of those that
// finished.
type shipState struct {
	sh      *audit.Shipper // nil when shipping is disabled
	retired []*audit.Shipper
	base    totals
}

// totals are counters of shippers that have finished.
type totals struct{ sent, dropped, reconnects uint64 }

func (t totals) plus(st audit.ShipperStats) totals {
	return totals{sent: t.sent + st.Sent, dropped: t.dropped + st.Dropped, reconnects: t.reconnects + st.Reconnects}
}

func (s *Service) loadState() shipState {
	if p := s.state.Load(); p != nil {
		return *p
	}
	return shipState{}
}

// current is the running shipper (nil when disabled).
func (s *Service) current() *audit.Shipper { return s.loadState().sh }

// publish makes next current and moves retire (if any) to the retired list, in one
// store. The caller holds mu.
func (s *Service) publish(next, retire *audit.Shipper) {
	cur := s.loadState()
	st := shipState{sh: next, retired: append([]*audit.Shipper(nil), cur.retired...), base: cur.base}
	if retire != nil {
		st.retired = append(st.retired, retire)
	}
	s.state.Store(&st)
}

// fold moves a finished shipper's final counters into the totals, in one store.
func (s *Service) fold(done *audit.Shipper) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.loadState()
	st := shipState{sh: cur.sh, base: cur.base}
	for _, r := range cur.retired {
		if r == done {
			st.base = st.base.plus(r.Stats())
			continue
		}
		st.retired = append(st.retired, r)
	}
	s.state.Store(&st)
}

// Stats is the running shipper's state (the zero value when shipping is disabled):
// /readyz, /metrics and the Overview banner read it. Sent, dropped and reconnects are
// totals over every shipper since start, so a swap never resets or dips them.
func (s *Service) Stats() audit.ShipperStats {
	cur := s.loadState()
	if cur.sh == nil {
		return audit.ShipperStats{}
	}
	st := cur.sh.Stats()
	t := cur.base
	for _, r := range cur.retired {
		t = t.plus(r.Stats())
	}
	st.Sent += t.sent
	st.Dropped += t.dropped
	st.Reconnects += t.reconnects
	return st
}

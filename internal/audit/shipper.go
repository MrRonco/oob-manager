package audit

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

// Shipper sends GELF frames to a log server over TCP or TLS from a single goroutine
// (Run). Enqueue never blocks: when the bounded queue is full (server down or slow)
// the message is dropped and counted. While the server is down the worker holds one
// frame and retries with exponential backoff; everything else waits in the queue. A
// TLS certificate that does not match the pin pauses dialling for PinPause (tech_doc
// §34): nothing is sent to an impostor, rows keep queueing.
type Shipper struct {
	cfg   ShipperConfig
	log   *slog.Logger
	queue chan []byte
	probe chan probeReq

	sent        atomic.Uint64
	dropped     atomic.Uint64
	reconnects  atomic.Uint64
	connected   atomic.Bool
	mismatch    atomic.Bool            // pin mismatch seen, no good handshake since
	pausedUntil atomic.Int64           // unix nanoseconds; no dial before
	pauseClass  atomic.Pointer[string] // why dialling is paused (tls_pin or tls_expired)
	lastClass   atomic.Pointer[string]
	lastSuccess atomic.Int64 // unix nanoseconds of the last written frame
	since       atomic.Int64 // unix nanoseconds of the current connection

	closed  atomic.Bool // Run has returned: Enqueue refuses
	holding atomic.Bool // deliver holds a dequeued frame
	// accepted counts frames queued; settled those written or dropped after being queued;
	// lost those dropped after being queued (WaitSent).
	accepted, settled, lost atomic.Uint64

	conn    net.Conn // owned by the Run goroutine
	held    []byte   // owned by the Run goroutine: a frame deliver gave back on cancel
	everUp  bool     // owned by the Run goroutine: a connection succeeded before
	pending bool     // owned by the Run goroutine: report recovery on the next write
}

// ShipperStats is a point-in-time view for /readyz, metrics and the Integrations page.
// The zero value (Active false) means no shipper is configured.
type ShipperStats struct {
	Active    bool
	TLS       bool
	Queued    int
	Sent      uint64
	Dropped   uint64
	Connected bool
	// PinMismatch: the server's certificate did not match the pin; shipping is paused
	// (and retried every PinPause) until a handshake succeeds.
	PinMismatch bool
	// PauseReason is ClassTLSPin or ClassTLSExpired while PinMismatch is set (it is not
	// overwritten by later failures such as a probe that cannot connect).
	PauseReason string
	Reconnects  uint64
	// LastError is the class of the most recent failure (ClassDial, ClassTLSPin, ...),
	// "" before any; never server-supplied text.
	LastError      string
	LastSuccess    time.Time
	ConnectedSince time.Time
}

type probeReq struct {
	frame []byte
	reply chan error
}

// NewShipper validates cfg and returns an idle shipper; call Run to start sending.
// log should write somewhere other than this shipper (avoid feedback loops); nil
// means slog.Default().
func NewShipper(cfg ShipperConfig, log *slog.Logger) (*Shipper, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	cfg = cfg.withDefaults()
	return &Shipper{cfg: cfg, log: log, queue: make(chan []byte, cfg.QueueSize), probe: make(chan probeReq)}, nil
}

// Enqueue encodes m and queues it without blocking. It returns false (and counts a
// drop) if the message is unencodable, oversized, the queue is full, or the shipper has
// finished (its Run returned: nothing would ever send it).
func (s *Shipper) Enqueue(m Message) bool {
	frame, err := m.encode()
	if err != nil || len(frame) > MaxMessageBytes || s.closed.Load() {
		s.dropped.Add(1)
		return false
	}
	select {
	case s.queue <- frame:
		s.accepted.Add(1)
	default:
		s.dropped.Add(1)
		return false
	}
	if s.closed.Load() { // Run finished meanwhile: whoever drains counts the frame once
		s.drainDropped()
		return false
	}
	return true
}

// dropQueued counts n frames dropped after they were queued.
func (s *Shipper) dropQueued(n uint64) {
	s.dropped.Add(n)
	s.settled.Add(n)
	s.lost.Add(n)
}

// drainDropped empties the queue, counting every frame as dropped.
func (s *Shipper) drainDropped() {
	for {
		select {
		case <-s.queue:
			s.dropQueued(1)
		default:
			return
		}
	}
}

// Probe makes one synchronous delivery attempt of m through the running worker (Send
// test): nil when the frame was written to the connection, else a *ShipError with the
// failure's class. It may dial during a pin pause (the pin is still checked, and
// nothing is written before it passes); a good handshake ends the pause. It waits at
// most until ctx ends (class timeout), so a shipper that is not running cannot hang the
// caller.
func (s *Shipper) Probe(ctx context.Context, m Message) error {
	frame, err := m.encode()
	if err != nil || len(frame) > MaxMessageBytes {
		return &ShipError{Class: ClassEncode}
	}
	req := probeReq{frame: frame, reply: make(chan error, 1)}
	select {
	case s.probe <- req:
	case <-ctx.Done():
		return &ShipError{Class: ClassTimeout}
	}
	select {
	case err := <-req.reply:
		return err
	case <-ctx.Done():
		return &ShipError{Class: ClassTimeout}
	}
}

// WaitSent waits until every frame queued when it was called has been written or
// dropped, and reports true only when that happened before ctx ended and none was
// dropped meanwhile. The
// integrations service uses it so the row recording a change of destination reaches
// the previous destination before the swap.
func (s *Shipper) WaitSent(ctx context.Context) bool {
	target, lost := s.accepted.Load(), s.lost.Load()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for s.settled.Load() < target {
		select {
		case <-ctx.Done():
			return false
		case <-tick.C:
		}
	}
	return s.lost.Load() == lost
}

// Stats returns current counters.
func (s *Shipper) Stats() ShipperStats {
	st := ShipperStats{Active: true, TLS: s.cfg.TLS != nil, Queued: len(s.queue), Sent: s.sent.Load(),
		Dropped: s.dropped.Load(), Connected: s.connected.Load(), PinMismatch: s.mismatch.Load(),
		Reconnects: s.reconnects.Load(), LastSuccess: unixTime(s.lastSuccess.Load())}
	if st.Connected {
		st.ConnectedSince = unixTime(s.since.Load())
	}
	if c := s.lastClass.Load(); c != nil {
		st.LastError = *c
	}
	if c := s.pauseClass.Load(); c != nil && st.PinMismatch {
		st.PauseReason = *c
	}
	return st
}

func unixTime(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).UTC()
}

// Run sends queued frames until ctx is cancelled, then flushes what it can within
// FlushTimeout and closes the connection. Afterwards Enqueue refuses and counts.
func (s *Shipper) Run(ctx context.Context) {
	defer func() {
		s.closeConn()
		s.closed.Store(true)
		s.drainDropped()
	}()
	for {
		if ctx.Err() != nil {
			s.flush()
			return
		}
		select {
		case <-ctx.Done():
		case req := <-s.probe:
			req.reply <- s.send(ctx, req.frame, true)
		case frame := <-s.queue:
			s.deliver(ctx, frame)
		}
	}
}

// deliver retries one frame with backoff until it is written or ctx ends (the frame
// is then kept for flush). Probes are answered while it waits.
func (s *Shipper) deliver(ctx context.Context, frame []byte) {
	s.holding.Store(true)
	defer s.holding.Store(false)
	backoff := s.cfg.BackoffMin
	for {
		if s.send(ctx, frame, false) == nil {
			s.settled.Add(1)
			return
		}
		wait := time.NewTimer(backoff)
	waiting:
		for {
			select {
			case <-ctx.Done():
				wait.Stop()
				s.held = frame
				return
			case req := <-s.probe:
				req.reply <- s.send(ctx, req.frame, true)
			case <-wait.C:
				break waiting
			}
		}
		backoff = min(backoff*2, s.cfg.BackoffMax)
	}
}

// flush sends the held frame and what is queued within FlushTimeout; whatever is left
// when it gives up (timeout or a failed send) is counted as dropped.
func (s *Shipper) flush() {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.FlushTimeout)
	defer cancel()
	defer s.drainDropped()
	if s.held != nil {
		frame := s.held
		s.held = nil
		if s.send(ctx, frame, false) != nil {
			s.dropQueued(1)
			return
		}
		s.settled.Add(1)
	}
	for ctx.Err() == nil {
		select {
		case frame := <-s.queue:
			if s.send(ctx, frame, false) != nil {
				s.dropQueued(1)
				return
			}
			s.settled.Add(1)
		default:
			return
		}
	}
}

// send writes one frame (dialling first when needed). Errors are *ShipError carrying
// the class recorded for the failure. probe lets a dial ignore a pin pause.
func (s *Shipper) send(ctx context.Context, frame []byte, probe bool) error {
	if s.conn == nil {
		if err := s.dial(ctx, probe); err != nil {
			return err
		}
	}
	if err := s.conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout)); err != nil {
		return s.fail(ClassWrite, err)
	}
	if _, err := s.conn.Write(frame); err != nil {
		return s.fail(ClassWrite, err)
	}
	s.sent.Add(1)
	s.lastSuccess.Store(s.cfg.Now().UnixNano())
	if s.pending {
		s.pending = false
		if s.cfg.OnRecovered != nil {
			s.cfg.OnRecovered()
		}
	}
	return nil
}

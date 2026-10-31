package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func listen(t *testing.T) (net.Listener, <-chan map[string]any) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	out := make(chan map[string]any, 100)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go readFrames(c, out)
		}
	}()
	return ln, out
}

func readFrames(c net.Conn, out chan<- map[string]any) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		frame, err := r.ReadBytes(0)
		if err != nil {
			return
		}
		var m map[string]any
		if json.Unmarshal(frame[:len(frame)-1], &m) == nil {
			out <- m
		}
	}
}

func fastConfig(addr string) ShipperConfig {
	return ShipperConfig{Address: addr, QueueSize: 8, DialTimeout: 200 * time.Millisecond,
		WriteTimeout: 200 * time.Millisecond, BackoffMin: 5 * time.Millisecond, BackoffMax: 20 * time.Millisecond,
		FlushTimeout: 200 * time.Millisecond}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestShipperDelivers(t *testing.T) {
	ln, got := listen(t)
	s, err := NewShipper(fastConfig(ln.Addr().String()), quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	msg := Message{Host: "oob-manager", Short: "power.GracefulRestart by morgan", Timestamp: t0, Level: LevelInfo,
		Fields: map[string]any{"audit_seq": int64(3), "bad key!": "x", "id": "reserved"}}
	if !s.Enqueue(msg) {
		t.Fatal("Enqueue refused on empty queue")
	}
	select {
	case m := <-got:
		if m["version"] != "1.1" || m["host"] != "oob-manager" || m["short_message"] != msg.Short {
			t.Errorf("frame = %v", m)
		}
		if m["_audit_seq"] != float64(3) || m["_bad_key_"] != "x" || m["_id"] != nil || m["_id_"] != "reserved" {
			t.Errorf("fields = %v", m)
		}
		if ts, _ := m["timestamp"].(float64); ts != float64(t0.UnixMilli())/1000 {
			t.Errorf("timestamp = %v", m["timestamp"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no frame received")
	}
	waitFor(t, func() bool { return s.Stats().Sent == 1 && s.Stats().Connected })
	cancel()
	<-done
}

func TestShipperNeverBlocksWhenGraylogDown(t *testing.T) {
	var up atomic.Bool
	ln, got := listen(t)
	cfg := fastConfig(ln.Addr().String())
	cfg.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !up.Load() {
			return nil, errors.New("connection refused")
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	s, err := NewShipper(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	start := time.Now()
	var accepted uint64
	for i := 0; i < 1000; i++ {
		if s.Enqueue(Message{Short: "x", Timestamp: t0}) {
			accepted++
		}
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Enqueue blocked: 1000 calls took %v", elapsed)
	}
	st := s.Stats()
	if st.Dropped == 0 || st.Dropped+accepted != 1000 || st.Connected {
		t.Errorf("stats while down = %+v (accepted %d)", st, accepted)
	}
	waitFor(t, func() bool { return s.Stats().LastError != "" })

	up.Store(true)
	for i := uint64(0); i < accepted; i++ {
		select {
		case <-got:
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d/%d queued messages delivered after recovery", i, accepted)
		}
	}
	waitFor(t, func() bool { return s.Stats().Queued == 0 && s.Stats().Sent == accepted })
}

func TestShipperReconnectsAfterServerDrop(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	s, err := NewShipper(fastConfig(addr), quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	s.Enqueue(Message{Short: "one", Timestamp: t0}) // the shipper dials lazily
	first, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return s.Stats().Sent == 1 })
	_ = first.Close()
	_ = ln.Close()

	// Keep sending until a write fails and the shipper reconnects to a new listener.
	ln2, got := listenOn(t, addr)
	defer ln2.Close()
	waitFor(t, func() bool {
		s.Enqueue(Message{Short: "again", Timestamp: t0})
		select {
		case <-got:
			return true
		default:
			return false
		}
	})
}

func listenOn(t *testing.T, addr string) (net.Listener, <-chan map[string]any) {
	t.Helper()
	var ln net.Listener
	var err error
	waitFor(t, func() bool { ln, err = (&net.ListenConfig{}).Listen(t.Context(), "tcp", addr); return err == nil })
	out := make(chan map[string]any, 100)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go readFrames(c, out)
		}
	}()
	return ln, out
}

func TestShipperDropsOversized(t *testing.T) {
	s, err := NewShipper(fastConfig("127.0.0.1:1"), quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if s.Enqueue(Message{Short: strings.Repeat("x", MaxMessageBytes)}) {
		t.Error("oversized message accepted")
	}
	if s.Stats().Dropped != 1 {
		t.Errorf("dropped = %d", s.Stats().Dropped)
	}
}

func TestShipperConfigValidation(t *testing.T) {
	for _, addr := range []string{"", "graylog", "graylog:"} {
		if _, err := NewShipper(ShipperConfig{Address: addr}, nil); err == nil {
			t.Errorf("address %q accepted", addr)
		}
	}
	s, err := NewShipper(ShipperConfig{Address: "192.0.2.45:12201"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.QueueSize != DefaultQueueSize || s.cfg.BackoffMax != DefaultBackoffMax || s.cfg.Dial == nil {
		t.Errorf("defaults not applied: %+v", s.cfg)
	}
}

func TestShipperRunStopsWhileDown(t *testing.T) {
	cfg := fastConfig("127.0.0.1:1")
	cfg.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("down") }
	s, err := NewShipper(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	s.Enqueue(Message{Short: "x"})
	waitFor(t, func() bool { return s.Stats().LastError != "" })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on cancel")
	}
}

func TestShipperFlushesOnShutdown(t *testing.T) {
	ln, got := listen(t)
	cfg := fastConfig(ln.Addr().String())
	cfg.QueueSize = 50
	s, err := NewShipper(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		s.Enqueue(Message{Short: "pending", Timestamp: t0})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: Run must still flush what it can within FlushTimeout
	s.Run(ctx)
	n := 0
	for n < 20 {
		select {
		case <-got:
			n++
		case <-time.After(2 * time.Second):
			t.Fatalf("flushed %d/20", n)
		}
	}
}

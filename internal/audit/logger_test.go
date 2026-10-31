package audit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/store"
)

type captureSink struct {
	mu   sync.Mutex
	msgs []Message
	full bool
}

func (c *captureSink) Enqueue(m Message) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.full {
		return false
	}
	c.msgs = append(c.msgs, m)
	return true
}

func TestRecordChainsAndShips(t *testing.T) {
	repo := &memRepo{}
	sink := &captureSink{}
	lg := NewLogger(repo, sink, fixedClock(), quietLogger())
	ctx := context.Background()

	first, err := lg.Record(ctx, entry(1))
	if err != nil {
		t.Fatal(err)
	}
	if first.Seq != 1 || first.PrevHash != GenesisHash || first.RowHash != Hash(first) {
		t.Errorf("first = %+v", first)
	}
	if first.TS.Nanosecond()%int(time.Millisecond) != 0 {
		t.Error("timestamp must be truncated to the stored millisecond precision")
	}
	if first.ParamsJSON != `{"confirm":true,"n":1}` {
		t.Errorf("params = %s", first.ParamsJSON)
	}
	second, err := lg.Record(ctx, entry(2))
	if err != nil {
		t.Fatal(err)
	}
	if second.Seq != 2 || second.PrevHash != first.RowHash {
		t.Errorf("second not chained: %+v", second)
	}
	if len(sink.msgs) != 2 {
		t.Fatalf("shipped %d messages", len(sink.msgs))
	}
	m := sink.msgs[1]
	if m.Fields["audit_seq"] != int64(2) || m.Fields["row_hash"] != second.RowHash || m.Fields["action"] != "power.GracefulRestart" {
		t.Errorf("gelf fields = %v", m.Fields)
	}
	if !strings.Contains(m.Short, "power.GracefulRestart") || !strings.Contains(m.Short, "morgan") {
		t.Errorf("short = %q", m.Short)
	}
}

func TestRecordDefaultsAndValidation(t *testing.T) {
	lg := NewLogger(&memRepo{}, nil, nil, nil)
	ctx := context.Background()
	e := entry(1)
	e.CorrelationID, e.Params = "", nil
	rec, err := lg.Record(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.CorrelationID) != 32 || rec.ParamsJSON != "{}" {
		t.Errorf("defaults: corr=%q params=%q", rec.CorrelationID, rec.ParamsJSON)
	}
	bad := []func(e *Entry){
		func(e *Entry) { e.Action = "" },
		func(e *Entry) { e.Principal = "" },
		func(e *Entry) { e.Result = "" },
		func(e *Entry) { e.Params = map[string]any{"big": strings.Repeat("x", MaxParamsBytes)} },
		func(e *Entry) { e.Params = map[string]any{"ch": make(chan int)} },
	}
	for i, mut := range bad {
		e := entry(i)
		mut(&e)
		if _, err := lg.Record(ctx, e); !errors.Is(err, ErrInvalidEntry) {
			t.Errorf("case %d: err = %v", i, err)
		}
	}
}

func TestRecordStoreFailureIsReturned(t *testing.T) {
	sink := &captureSink{}
	lg := NewLogger(&memRepo{appendErr: errors.New("disk full")}, sink, fixedClock(), quietLogger())
	if _, err := lg.Record(context.Background(), entry(1)); err == nil {
		t.Fatal("store failure swallowed")
	}
	if len(sink.msgs) != 0 {
		t.Error("message shipped for an unrecorded action")
	}
}

func TestRecordSucceedsWhenSinkFull(t *testing.T) {
	sink := &captureSink{full: true}
	repo := &memRepo{}
	lg := NewLogger(repo, sink, fixedClock(), quietLogger())
	for i := 0; i < 3; i++ {
		if _, err := lg.Record(context.Background(), entry(i)); err != nil {
			t.Fatalf("Record with full sink: %v", err)
		}
	}
	if len(repo.recs) != 3 {
		t.Errorf("recorded %d", len(repo.recs))
	}
}

func TestRecordConcurrentKeepsChain(t *testing.T) {
	repo := &memRepo{}
	lg := NewLogger(repo, nil, time.Now, quietLogger())
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := lg.Record(context.Background(), entry(i)); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if _, err := Verify(context.Background(), repo, 7); err != nil {
		t.Fatalf("Verify after concurrent writes: %v", err)
	}
}

var _ store.AuditRepository = (*memRepo)(nil)

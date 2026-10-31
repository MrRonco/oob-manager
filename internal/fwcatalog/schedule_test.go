package fwcatalog

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/firmware/catalog/catalogtest"
	"oob-manager/internal/notify"
	"oob-manager/internal/store"
)

type emits struct {
	mu sync.Mutex
	ev []notify.Event
}

func (e *emits) emit(ev notify.Event) { e.mu.Lock(); e.ev = append(e.ev, ev); e.mu.Unlock() }
func (e *emits) all() []notify.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]notify.Event(nil), e.ev...)
}

type schedEnv struct {
	f       *fixture
	c       *Checker
	srv     *catalogServer
	enabled atomic.Bool
	notify  atomic.Value // string
	emits   *emits
	rec     *recAudit
}

func newSchedEnv(t *testing.T) *schedEnv {
	t.Helper()
	f := newFixture(t)
	data := catalogtest.Catalog()
	e := &schedEnv{f: f, srv: newCatalogServer(t, data, f.key.Sign(t, data)), emits: &emits{}, rec: &recAudit{}}
	e.notify.Store("urgent")
	fe := e.srv.fetcher()
	pending := []Pending{
		{ServerID: "a", ServerName: "A", ComponentID: "159", Component: "BIOS", Running: "1", Latest: "2"},
		{ServerID: "a", ServerName: "A", ComponentID: "25227", Component: "iDRAC", Running: "7.0", Latest: "7.1", Urgent: true},
		{ServerID: "m", ServerName: "M", ComponentID: "25227", Component: "iDRAC", Running: "7.0", Latest: "7.1", Urgent: true},
	}
	c, err := NewChecker(CheckerConfig{Importer: f.im, Repo: f.db.Catalog(), Updates: f.db.FirmwareUpdates(), Audit: e.rec,
		Online: Online{Fetcher: &fe, Tick: 5 * time.Millisecond, FirstDelay: func() time.Duration { return 0 },
			Schedule: func() Schedule {
				level, _ := e.notify.Load().(string)
				return Schedule{Enabled: e.enabled.Load(), Every: time.Hour, Notify: level}
			},
			Pending:       func(context.Context) []Pending { return pending },
			InMaintenance: func(id string) bool { return id == "m" },
			Emit:          e.emits.emit}})
	if err != nil {
		t.Fatal(err)
	}
	e.c = c
	return e
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for range 400 {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestScheduleOffSendsNothingThenChecksWhenTurnedOn(t *testing.T) {
	e := newSchedEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.c.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	time.Sleep(60 * time.Millisecond)
	if n := len(e.srv.asked()); n != 0 {
		t.Fatalf("%d requests while the check is off", n)
	}
	e.enabled.Store(true)
	waitFor(t, "an import", func() bool {
		_, ok, _ := e.f.db.Catalog().Import(context.Background(), "dell", store.CatalogActive)
		return ok
	})
	waitFor(t, "a notification", func() bool { return len(e.emits.all()) == 1 })
	ev := e.emits.all()[0]
	if ev.Class != notify.ClassFirmware || ev.Severity != notify.SeverityWarning || ev.Count != 1 {
		t.Fatalf("event %+v (urgent only, the server in maintenance waits)", ev)
	}
	// Check now re-fetches; the ETag answers 304, nothing new is notified.
	a := admin.Actor{Username: "olga", Method: "session", Role: "operator"}
	if err := e.c.CheckNow(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a not_modified check", func() bool {
		cs, _ := e.f.db.Catalog().Checks(context.Background(), "dell", 1)
		return len(cs) == 1 && cs[0].Result == "not_modified"
	})
	var wait *WaitError
	if err := e.c.CheckNow(context.Background(), a); !errors.As(err, &wait) || wait.Left <= 0 {
		t.Fatalf("second Check now: %v", err)
	}
	if len(e.emits.all()) != 1 {
		t.Fatalf("notified twice: %+v", e.emits.all())
	}
	e.enabled.Store(false)
	if err := e.c.CheckNow(context.Background(), a); !errors.Is(err, ErrCheckOff) {
		t.Fatalf("check while off: %v", err)
	}
	if st := e.c.Status(context.Background()); st.Enabled || !st.Online {
		t.Fatalf("status %+v", st)
	}
}

func TestScheduleFailuresAlertOnceAndRetry(t *testing.T) {
	e := newSchedEnv(t)
	e.srv.h = func(w http.ResponseWriter, _ *http.Request) bool { w.WriteHeader(http.StatusBadGateway); return true }
	s := Schedule{Enabled: true, Every: 24 * time.Hour}
	ctx := context.Background()
	waits := []time.Duration{e.c.checkOnline(ctx, s), e.c.checkOnline(ctx, s), e.c.checkOnline(ctx, s), e.c.checkOnline(ctx, s)}
	if waits[0] != time.Hour || waits[1] != 6*time.Hour || waits[2] != 24*time.Hour {
		t.Fatalf("retry ladder %v", waits)
	}
	if ev := e.emits.all(); len(ev) != 1 || ev[0].Key != "firmware/check" {
		t.Fatalf("failure alerts %+v", ev)
	}
	_, _, last, failures := e.c.Metrics(ctx)
	if failures["download"] != 4 || last != "download" {
		t.Fatalf("metrics %v %q", failures, last)
	}
	e.srv.h = nil
	if w := e.c.checkOnline(ctx, s); w != 24*time.Hour {
		t.Fatalf("after success %v", w)
	}
	e.srv.h = func(w http.ResponseWriter, _ *http.Request) bool { w.WriteHeader(http.StatusBadGateway); return true }
	for range 3 {
		e.c.checkOnline(ctx, s)
	}
	if len(e.emits.all()) != 3 { // a new failure streak alerts again (the success in between notified the updates)
		t.Fatalf("alerts %+v", e.emits.all())
	}
}

func TestUploadAndConfirmHeld(t *testing.T) {
	e := newSchedEnv(t)
	ctx := context.Background()
	a := admin.Actor{Username: "alice", Method: "session", Role: "admin"}
	data := catalogtest.Catalog()
	if _, err := e.c.Upload(ctx, a, bytes.NewReader(data), nil); catalog.Class(err) != "signature" {
		t.Fatalf("unsigned upload: %v", err)
	}
	res, err := e.c.Upload(ctx, a, bytes.NewReader(data), e.f.key.Sign(t, data))
	if err != nil || res.State != store.CatalogActive {
		t.Fatalf("upload %+v %v", res, err)
	}
	imp, _, _ := e.f.db.Catalog().Import(ctx, "dell", store.CatalogActive)
	if imp.Origin != OriginUpload || imp.ImportedBy != "alice" {
		t.Fatalf("import %+v", imp)
	}
	if err := e.c.ConfirmHeld(ctx, a, 1); !errors.Is(err, ErrNothingHeld) {
		t.Fatalf("confirm without a held catalog: %v", err)
	}
	if _, err := e.c.Upload(ctx, a, bytes.NewReader(make([]byte, MaxCatalogBytes+1)), nil); !errors.Is(err, catalog.ErrSize) {
		t.Fatalf("oversize upload: %v", err)
	}
	e.c.EnabledChanged(ctx, a, false, true)
	if got := e.rec.entries[len(e.rec.entries)-1]; got.Action != ActionEnabled || got.Params["after"] != true {
		t.Fatalf("audit %+v", got)
	}
	if e.c.File().URL != "" {
		t.Fatal("file settings")
	}
}

func TestNotifyLevelsMaintenanceAndThe304(t *testing.T) {
	e := newSchedEnv(t)
	ctx := context.Background()
	e.notify.Store("off")
	e.c.notifyNew(ctx)
	if len(e.emits.all()) != 0 {
		t.Fatal("notified with level off")
	}
	// Everything seen was marked: switching to all does not re-send it; the server in
	// maintenance was not marked, so it is sent once its window is over.
	e.notify.Store("all")
	e.c.notifyNew(ctx)
	if len(e.emits.all()) != 0 {
		t.Fatalf("re-sent after the level changed: %+v", e.emits.all())
	}
	o := e.c.online()
	o.InMaintenance = func(string) bool { return false }
	e.c.SetOnline(o)
	e.enabled.Store(true)
	// A 304 re-evaluates: the update of the server whose window ended goes out.
	if err := e.f.db.Catalog().AddCheck(ctx, store.CatalogCheckRow{Source: "dell", At: time.Now(), Result: "x"}); err == nil {
		t.Fatal("bogus result stored")
	}
	data := catalogtest.Catalog()
	if _, err := e.f.im.Import(ctx, Input{Origin: OriginOnline, File: e.f.stage(t, data), Sig: e.f.key.Sign(t, data), ETag: `"v1"`}); err != nil {
		t.Fatal(err)
	}
	e.c.checkOnline(ctx, Schedule{Enabled: true, Every: time.Hour, Notify: "all"})
	ev := e.emits.all()
	if len(ev) != 1 || ev[0].Count != 1 || !strings.Contains(ev[0].Message, "M: iDRAC") {
		t.Fatalf("after the window: %+v", ev)
	}
	if hits := e.srv.asked(); len(hits) != 1 || hits[0] != "/c.xml.gz" {
		t.Fatalf("the 304 path fetched %v", hits)
	}
}

func TestKickWhileOffAndConfirmHeld(t *testing.T) {
	e := newSchedEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	o := e.c.online()
	o.FirstDelay = func() time.Duration { return time.Hour }
	e.c.SetOnline(o)
	go func() { e.c.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	e.c.kick <- struct{}{} // a stale kick while the check is off
	time.Sleep(50 * time.Millisecond)
	if n := len(e.srv.asked()); n != 0 {
		t.Fatalf("%d requests while off", n)
	}
	a := admin.Actor{Username: "alice", Role: "admin", IP: "192.0.2.4"}
	data := catalogtest.Catalog()
	bg := context.Background()
	if _, err := e.c.Upload(bg, a, bytes.NewReader(data), e.f.key.Sign(t, data)); err != nil {
		t.Fatal(err)
	}
	smaller := catalogtest.Encode(strings.ReplaceAll(catalogtest.XML(), `systemID="088F"`, `systemID="0999"`))
	res, err := e.c.Upload(bg, a, bytes.NewReader(smaller), e.f.key.Sign(t, smaller))
	if err != nil || res.State != store.CatalogHeld {
		t.Fatalf("held %+v %v", res, err)
	}
	if err := e.c.ConfirmHeld(bg, a, res.ImportID+1); !errors.Is(err, ErrNothingHeld) {
		t.Fatalf("another import id: %v", err)
	}
	if err := e.c.ConfirmHeld(bg, a, res.ImportID); err != nil {
		t.Fatal(err)
	}
	last := e.rec.entries[len(e.rec.entries)-1]
	if last.Action != ActionConfirm || last.Params["sha256"] != res.SHA256 {
		t.Fatalf("confirm audit %+v", last)
	}
	imp, _, _ := e.f.db.Catalog().Import(bg, "dell", store.CatalogActive)
	if imp.ID != res.ImportID {
		t.Fatalf("active %+v", imp)
	}
}

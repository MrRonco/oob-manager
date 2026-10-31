package hostlease

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/fan"
)

func newApplier(t *testing.T, now time.Time) (*Applier, string) {
	t.Helper()
	dir := t.TempDir()
	a, err := New(Config{Dir: dir, ServerID: "node-a", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return a, dir
}

func writeAck(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "node-a.ack"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func ackFor(id, owner, pct string, at int64) string {
	return "version=1\nserver=node-a\nlease_id=" + id + "\nowner=" + owner + "\napplied_pct=" + pct +
		"\nreported_at=" + itoa(at) + "\nreason=ok\n"
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

func TestApplyWritesLeaseAtomically(t *testing.T) {
	l := testLease()
	a, dir := newApplier(t, l.IssuedAt)
	plan, err := a.Prepare(context.Background(), 55, 30)
	if err != nil || plan.Pct != 55 || plan.HasOriginal {
		t.Fatalf("plan = %+v %v", plan, err)
	}
	immediate, err := a.Apply(context.Background(), l)
	if err != nil || immediate {
		t.Fatalf("apply = %v %v (a host lease is never immediate)", immediate, err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "node-a.lease")) //nolint:gosec // G304: test temp dir
	want, _ := os.ReadFile("testdata/golden.lease")
	if string(got) != string(want) {
		t.Fatalf("lease file = %q", got)
	}
	fi, _ := os.Stat(filepath.Join(dir, "node-a.lease"))
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
	// Idempotent: a second Apply (startup) replaces the file in place.
	if _, err := a.Apply(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	if err := a.Release(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "node-a.lease")); !os.IsNotExist(err) {
		t.Fatalf("lease file still there: %v", err)
	}
	if err := a.Release(context.Background(), l); err != nil {
		t.Fatalf("second release: %v", err)
	}
}

func TestApplyRefusesBadLeaseAndBadDir(t *testing.T) {
	l := testLease()
	a, _ := newApplier(t, l.IssuedAt)
	l.Pct = 101
	if _, err := a.Apply(context.Background(), l); err == nil {
		t.Fatal("bad lease written")
	}
	missing, err := New(Config{Dir: filepath.Join(t.TempDir(), "absent"), ServerID: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missing.Apply(context.Background(), testLease()); err == nil {
		t.Fatal("missing directory accepted")
	}
	if err := missing.Release(context.Background(), testLease()); err == nil {
		t.Fatal("missing directory release accepted")
	}
	for _, c := range []Config{{Dir: "relative", ServerID: "node-a"}, {Dir: "/tmp", ServerID: "Bad ID"}, {ServerID: "node-a"}} {
		if _, err := New(c); err == nil {
			t.Errorf("New(%+v) accepted", c)
		}
	}
}

func TestSweepRemovesStrayLease(t *testing.T) {
	a, dir := newApplier(t, time.Unix(1_800_000_000, 0))
	if err := a.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(context.Background(), testLease()); err != nil {
		t.Fatal(err)
	}
	if err := a.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "node-a.lease")); !os.IsNotExist(err) {
		t.Fatal("stray lease file not swept")
	}
}

func TestObserve(t *testing.T) {
	l := testLease()
	issued := l.IssuedAt.Unix()
	cases := []struct {
		name     string
		ack      string // "" = no ack file
		at       time.Time
		has      bool
		applied  bool
		owner    fan.Owner
		pct      int
		warnPart string
	}{
		{"no ack, lease just issued", "", l.IssuedAt.Add(30 * time.Second), true, false, fan.OwnerUnknown, 0, ""},
		{"no ack, lease old", "", l.IssuedAt.Add(4 * time.Minute), true, false, fan.OwnerUnknown, 0, "No report"},
		{"no ack, no lease", "", l.IssuedAt, false, false, fan.OwnerUnknown, 0, "has not reported"},
		{"applied", ackFor(testID, "lease", "55", issued+60), l.IssuedAt.Add(90 * time.Second), true, true, fan.OwnerLease, 55, ""},
		{"curve above floor", ackFor(testID, "curve", "65", issued+60), l.IssuedAt.Add(time.Minute), true, true, fan.OwnerCurve, 65, ""},
		{"other lease", ackFor(strings.Repeat("f", 32), "lease", "55", issued+60), l.IssuedAt.Add(time.Minute), true, false, fan.OwnerLease, 55, ""},
		{"stale", ackFor(testID, "lease", "55", issued+60), l.IssuedAt.Add(10 * time.Minute), true, false, fan.OwnerLease, 55, "last reported"},
		{"guard", ackFor(testID, "guard", "auto", issued+60), l.IssuedAt.Add(time.Minute), true, false, fan.OwnerGuard, 0, "thermal guard"},
		{"curve, no lease", ackFor("none", "curve", "35", issued), l.IssuedAt, false, false, fan.OwnerCurve, 35, ""},
		{"garbage", "rm -rf /\n", l.IssuedAt, false, false, fan.OwnerUnknown, 0, "could not be read"},
		{"rejected", strings.Replace(ackFor(testID, "curve", "35", issued+60), "reason=ok", "reason=invalid", 1),
			l.IssuedAt.Add(time.Minute), true, false, fan.OwnerCurve, 35, "rejected"},
	}
	for _, c := range cases {
		a, dir := newApplier(t, c.at)
		if c.ack != "" {
			writeAck(t, dir, c.ack)
		}
		o := a.Observe(l, c.has)
		if o.Applied != c.applied || o.Owner != c.owner || o.AppliedPct != c.pct || !strings.Contains(o.Warning, c.warnPart) ||
			(c.warnPart == "" && o.Warning != "") {
			t.Errorf("%s: observation = %+v", c.name, o)
		}
	}
}

func TestObserveRefusesSymlinkAndOversize(t *testing.T) {
	l := testLease()
	a, dir := newApplier(t, l.IssuedAt.Add(time.Minute))
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte(ackFor(testID, "lease", "55", l.IssuedAt.Unix())), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "node-a.ack")); err != nil {
		t.Fatal(err)
	}
	if o := a.Observe(l, true); o.Applied || !strings.Contains(o.Warning, "could not be read") {
		t.Fatalf("symlinked ack trusted: %+v", o)
	}
	_ = os.Remove(filepath.Join(dir, "node-a.ack"))
	writeAck(t, dir, ackFor(testID, "lease", "55", l.IssuedAt.Unix())+strings.Repeat("x=1\n", 200))
	if o := a.Observe(l, true); o.Applied {
		t.Fatalf("oversized ack trusted: %+v", o)
	}
	_ = os.Remove(filepath.Join(dir, "node-a.ack"))
	if err := os.Mkdir(filepath.Join(dir, "node-a.ack"), 0o700); err != nil {
		t.Fatal(err)
	}
	if o := a.Observe(l, true); o.Applied || o.Warning == "" {
		t.Fatalf("directory ack: %+v", o)
	}
}

// Readers never see a partial lease file while it is being replaced.
func TestConcurrentApplyAndRead(t *testing.T) {
	l := testLease()
	a, dir := newApplier(t, l.IssuedAt)
	want, _ := encodeLease(l)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				if _, err := a.Apply(context.Background(), l); err != nil {
					t.Error(err)
					return
				}
			}
		}
	})
	for range 300 {
		b, err := os.ReadFile(filepath.Join(dir, "node-a.lease")) //nolint:gosec // G304: test temp dir
		if err == nil && string(b) != string(want) {
			t.Fatalf("partial read: %q", b)
		}
	}
	close(stop)
	wg.Wait()
}

package hostlease

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/fan"
	"oob-manager/internal/store"
)

const testID = "0123456789abcdef0123456789abcdef"

func testLease() store.FanLease {
	at := time.Unix(1_800_000_000, 0).UTC()
	return store.FanLease{LeaseID: testID, ServerID: "node-a", Mode: store.LeaseBoost, Pct: 55, IssuedAt: at,
		ExpiresAt: at.Add(30 * time.Minute), RequestedBy: "op", State: store.LeasePending}
}

func TestEncodeLeaseGolden(t *testing.T) {
	want, err := os.ReadFile("testdata/golden.lease")
	if err != nil {
		t.Fatal(err)
	}
	got, err := encodeLease(testLease())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("lease file:\n%s\nwant:\n%s", got, want)
	}
	if len(got) > MaxFileBytes {
		t.Fatalf("lease file is %d bytes, cap %d", len(got), MaxFileBytes)
	}
}

func TestEncodeLeaseRefusesBadValues(t *testing.T) {
	mut := []func(*store.FanLease){
		func(l *store.FanLease) { l.Pct = 101 },
		func(l *store.FanLease) { l.Pct = -1 },
		func(l *store.FanLease) { l.LeaseID = "short" },
		func(l *store.FanLease) { l.LeaseID = strings.ToUpper(testID) },
		func(l *store.FanLease) { l.ServerID = "Node A" },
		func(l *store.FanLease) { l.ServerID = "a\nb" },
		func(l *store.FanLease) { l.ExpiresAt = l.IssuedAt },
		func(l *store.FanLease) { l.IssuedAt = time.Time{} },
	}
	for i, m := range mut {
		l := testLease()
		m(&l)
		if _, err := encodeLease(l); err == nil {
			t.Errorf("case %d: encoded %+v", i, l)
		}
	}
}

func TestParseAckGolden(t *testing.T) {
	b, err := os.ReadFile("testdata/ack-applied.ack")
	if err != nil {
		t.Fatal(err)
	}
	a, err := parseAck(b, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	want := ack{LeaseID: testID, Owner: fan.OwnerLease, Pct: 55, HasPct: true,
		ReportedAt: time.Unix(1_800_000_060, 0).UTC(), Reason: "ok"}
	if a != want {
		t.Fatalf("ack = %+v", a)
	}
}

func TestParseAckVariants(t *testing.T) {
	base := "version=1\nserver=node-a\nlease_id=none\nowner=curve\napplied_pct=35\nreported_at=1800000060\nreason=none\n"
	a, err := parseAck([]byte(base), "node-a")
	if err != nil || a.LeaseID != "" || a.Owner != fan.OwnerCurve || a.Pct != 35 {
		t.Fatalf("curve ack = %+v %v", a, err)
	}
	guard := strings.Replace(strings.Replace(base, "owner=curve", "owner=guard", 1), "applied_pct=35", "applied_pct=auto", 1)
	a, err = parseAck([]byte(guard), "node-a")
	if err != nil || a.Owner != fan.OwnerGuard || a.HasPct {
		t.Fatalf("guard ack = %+v %v", a, err)
	}
	unknownKey := base + "future_key=1\n"
	if _, err := parseAck([]byte(unknownKey), "node-a"); err != nil {
		t.Fatalf("unknown keys are ignored: %v", err)
	}
	noNewline := strings.TrimSuffix(base, "\n")
	if _, err := parseAck([]byte(noNewline), "node-a"); err != nil {
		t.Fatalf("missing final newline: %v", err)
	}
}

func TestParseAckHostile(t *testing.T) {
	base := "version=1\nserver=node-a\nlease_id=none\nowner=curve\napplied_pct=35\nreported_at=1800000060\nreason=none\n"
	bad := map[string]string{
		"empty":        "",
		"version":      strings.Replace(base, "version=1", "version=2", 1),
		"server":       strings.Replace(base, "server=node-a", "server=node-b", 1),
		"owner":        strings.Replace(base, "owner=curve", "owner=root", 1),
		"pct range":    strings.Replace(base, "applied_pct=35", "applied_pct=101", 1),
		"pct sign":     strings.Replace(base, "applied_pct=35", "applied_pct=-5", 1),
		"time":         strings.Replace(base, "reported_at=1800000060", "reported_at=soon", 1),
		"lease id":     strings.Replace(base, "lease_id=none", "lease_id=../../etc", 1),
		"reason":       strings.Replace(base, "reason=none", "reason=<script>", 1),
		"duplicate":    base + "owner=lease\n",
		"missing":      strings.Replace(base, "owner=curve\n", "", 1),
		"no equals":    base + "garbage\n",
		"spaces":       strings.Replace(base, "owner=curve", "owner = curve", 1),
		"crlf":         strings.ReplaceAll(base, "\n", "\r\n"),
		"nul":          base + "x=\x00\n",
		"oversized":    base + strings.Repeat("pad=0\n", 200),
		"blank line":   "version=1\n\n" + strings.TrimPrefix(base, "version=1\n"),
		"long value":   strings.Replace(base, "reason=none", "reason="+strings.Repeat("a", 65), 1),
		"utf8":         strings.Replace(base, "owner=curve", "owner=cürve", 1),
		"many digits":  strings.Replace(base, "reported_at=1800000060", "reported_at=99999999999999999999", 1),
		"bad key char": base + "Bad-Key=1\n",
	}
	for name, doc := range bad {
		if _, err := parseAck([]byte(doc), "node-a"); !errors.Is(err, errBadAck) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

package hostlease

import (
	"testing"

	"oob-manager/internal/fan"
)

// FuzzLeaseAck: a hostile ack file (the host script writes it, so anything on the host
// that can write the lease directory controls it) either fails to parse or yields only
// the bounded fields an ack can carry: never a panic, a percentage over 100 or an
// unknown owner.
func FuzzLeaseAck(f *testing.F) {
	good := "version=1\nserver=node-a\nlease_id=0123456789abcdef0123456789abcdef\nowner=lease\napplied_pct=45\nreported_at=1792000000\nreason=applied\n"
	f.Add([]byte(good))
	f.Add([]byte("version=1\nserver=node-a\nlease_id=none\nowner=curve\napplied_pct=auto\nreported_at=1\nreason=x\n"))
	f.Add([]byte("version=1\nversion=1\n"))
	f.Add([]byte("applied_pct=999\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := parseAck(b, "node-a")
		if err != nil {
			return
		}
		if len(b) > MaxFileBytes {
			t.Fatalf("accepted %d bytes", len(b))
		}
		switch a.Owner {
		case fan.OwnerLease, fan.OwnerCurve, fan.OwnerGuard:
		default:
			t.Fatalf("owner %q", a.Owner)
		}
		if a.HasPct && (a.Pct < 0 || a.Pct > 100) {
			t.Fatalf("pct %d", a.Pct)
		}
		if a.LeaseID != "" && !leaseIDPattern.MatchString(a.LeaseID) {
			t.Fatalf("lease id %q", a.LeaseID)
		}
		if !reasonPattern.MatchString(a.Reason) {
			t.Fatalf("reason %q", a.Reason)
		}
	})
}

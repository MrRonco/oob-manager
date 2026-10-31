package hostlease

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	"oob-manager/internal/fan"
	"oob-manager/internal/store"
)

// User-facing warnings (US English, no internals).
const (
	warnUnreadable = "The host fan script's report could not be read."
	warnNoReport   = "The host fan script has not reported yet. Check that it is installed and runs every minute."
	warnNoAck      = "No report from the host fan script yet. Check that it runs every minute and can read the lease directory."
	warnGuard      = "A thermal guard is active: the BMC controls the fans until temperatures drop."
	warnRejected   = "The host fan script rejected the lease file."
)

// Observe reads the ack. It is applied when the host reported this lease's ID recently;
// a guard, a rejected file or a stale report becomes a warning.
func (a *Applier) Observe(l store.FanLease, has bool) fan.Observation {
	now := a.cfg.Now()
	ak, err := a.readAck()
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !has {
			return fan.Observation{Warning: warnNoReport}
		}
		if now.Sub(l.IssuedAt) > a.cfg.StaleAfter {
			return fan.Observation{Warning: warnNoAck}
		}
		return fan.Observation{}
	case err != nil:
		return fan.Observation{Warning: warnUnreadable}
	}
	o := fan.Observation{Owner: ak.Owner, AppliedPct: ak.Pct, HasPct: ak.HasPct, ReportedAt: ak.ReportedAt}
	if age := now.Sub(ak.ReportedAt); age > a.cfg.StaleAfter {
		o.Warning = fmt.Sprintf("The host fan script last reported %s ago. Check that it still runs.", ago(age))
		return o
	}
	switch {
	case ak.Owner == fan.OwnerGuard:
		o.Warning = warnGuard
	case has && ak.Reason == "invalid" && !ak.ReportedAt.Before(l.IssuedAt):
		o.Warning = warnRejected
	case has && ak.LeaseID == l.LeaseID:
		o.Applied = true
	}
	return o
}

// readAck opens the ack without following a symlink swapped in after the check (Lstat
// and the opened file must be the same regular file) and reads at most MaxFileBytes+1.
func (a *Applier) readAck() (ack, error) {
	root, err := os.OpenRoot(a.cfg.Dir)
	if err != nil {
		return ack{}, err
	}
	defer root.Close()
	li, err := root.Lstat(a.ackName())
	if err != nil {
		return ack{}, err
	}
	if !li.Mode().IsRegular() {
		return ack{}, errBadAck
	}
	f, err := root.Open(a.ackName())
	if err != nil {
		return ack{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !os.SameFile(li, fi) {
		return ack{}, errBadAck
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return ack{}, err
	}
	return parseAck(b, a.cfg.ServerID)
}

func ago(d time.Duration) string {
	m := int(d / time.Minute)
	switch {
	case m >= 120:
		return fmt.Sprintf("%d hours", m/60)
	case m == 1:
		return "1 minute"
	default:
		return fmt.Sprintf("%d minutes", m)
	}
}

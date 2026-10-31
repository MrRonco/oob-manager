package fleet

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

// cutOffDriver blocks until the cycle budget ends, then fails the way a response cut
// off mid-body can: with an error that is not a timeout by itself (ErrDecode), or
// with a pin mismatch, which must keep its own class.
type cutOffDriver struct {
	tierDriver
	err error
}

func (d *cutOffDriver) Snapshot(ctx context.Context) (bmc.Snapshot, error) {
	<-ctx.Done()
	return bmc.Snapshot{}, d.err
}

// TestBudgetExhaustedIsATimeout: a poll that ran out of its cycle budget is recorded
// as a timeout, whatever ambiguous error the driver returned as it was cut off (seen
// on CI as "protocol" for a hanging BMC); a pin mismatch keeps its class.
func TestBudgetExhaustedIsATimeout(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bmc.ErrorClass
	}{
		{"decode", fmt.Errorf("GET /redfish/v1/Systems: %w", bmc.ErrDecode), bmc.ClassTimeout},
		{"other", errors.New("unexpected EOF"), bmc.ClassTimeout},
		{"pin", fmt.Errorf("redfish: %w", bmc.ErrPinMismatch), bmc.ClassTLS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &cutOffDriver{err: tc.err}
			h := start(t, Config{Targets: []Target{target("x", "fx", d)}, CycleTimeout: 50 * time.Millisecond})
			waitFor(t, "a failure", func() bool { return h.state(t, "x").ConsecutiveFailures >= 1 })
			st := h.state(t, "x")
			if st.LastError != tc.want {
				t.Fatalf("LastError = %q, want %q", st.LastError, tc.want)
			}
			if tc.name == "pin" && (!st.Paused || !st.PinMismatch) {
				t.Fatalf("a pin mismatch must still pause polling: %+v", st)
			}
		})
	}
}

// TestBudgetClassOnlyRelabelsAmbiguousErrorsAfterTheBudget pins budgetClass itself:
// only a decode error or an unclassified one, and only once the poll's own budget
// expired while the parent context is alive.
func TestBudgetClassOnlyRelabelsAmbiguousErrorsAfterTheBudget(t *testing.T) {
	alive := context.Background()
	expired, cancelExpired := context.WithDeadline(alive, time.Now().Add(-time.Second))
	defer cancelExpired()
	cancelled, cancel := context.WithCancel(alive)
	cancel()
	decode := fmt.Errorf("GET /x: %w", bmc.ErrDecode)
	for _, tc := range []struct {
		name         string
		parent, cctx context.Context
		err          error
		want         bmc.ErrorClass
	}{
		{"decode after the budget", alive, expired, decode, bmc.ClassTimeout},
		{"bare EOF after the budget", alive, expired, errors.New("unexpected EOF"), bmc.ClassTimeout},
		{"decode within the budget", alive, alive, decode, bmc.ClassProtocol},
		{"method guard after the budget", alive, expired, fmt.Errorf("x: %w", bmc.ErrMethodNotAllowed), bmc.ClassProtocol},
		{"size cap after the budget", alive, expired, fmt.Errorf("x: %w", bmc.ErrResponseTooLarge), bmc.ClassProtocol},
		{"HTTP status after the budget", alive, expired, fmt.Errorf("x: %w", bmc.ErrBMC), bmc.ClassBMC},
		{"shutting down", cancelled, expired, decode, bmc.ClassProtocol},
		{"budget cancelled, not expired", alive, cancelled, decode, bmc.ClassProtocol},
	} {
		if got := bmc.Classify(budgetClass(tc.parent, tc.cctx, tc.err)); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if budgetClass(alive, expired, nil) != nil {
		t.Error("a nil error must stay nil")
	}
}

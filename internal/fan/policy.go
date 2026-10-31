// Package fan is the fan lease model and arbiter (docs/system_design.md §3): a lease is
// a time-boxed fan floor, persisted in SQLite, applied by one mode-specific Applier
// (hostlease: a file the host fan script honours; redfishfloor: the BMC's minimum fan
// speed) and reconciled at startup and on every tick, so expiry does not depend on the
// request that created the lease. Leases only ever raise fans: the floor is clamped up
// to the server's safe minimum and the enforcing side never goes below its own curve.
package fan

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"oob-manager/internal/config"
)

// MinLease is the shortest lease (PRD FR-11: 5–120 minutes).
const MinLease = 5 * time.Minute

// Errors. UI code maps them to messages; their text is safe to show.
var (
	ErrInvalid       = errors.New("fan: invalid lease request")
	ErrNotConfigured = errors.New("fan: fan control is not configured for this server")
	ErrActive        = errors.New("fan: a lease is already active")
	ErrNoLease       = errors.New("fan: no active lease")
	ErrApply         = errors.New("fan: the lease could not be applied")
	ErrRelease       = errors.New("fan: the lease could not be ended")
	ErrAudit         = errors.New("fan: audit record failed; nothing was changed")
)

// digits is the only accepted shape of a number in a request: 1–3 ASCII digits for a
// percentage, 1–4 for minutes. No sign, space, unit, exponent or other script.
var (
	pctPattern     = regexp.MustCompile(`^[0-9]{1,3}$`)
	minutesPattern = regexp.MustCompile(`^[0-9]{1,4}$`)
)

// Policy is one server's fan settings from config.
type Policy struct {
	ServerID string
	Mode     config.FanMode
	SafeMin  int
	MaxLease time.Duration
}

// PolicyFor builds the policy of a configured server.
func PolicyFor(s config.Server) Policy {
	return Policy{ServerID: s.ID, Mode: s.Fan.Mode, SafeMin: s.Fan.SafeMinPct, MaxLease: s.Fan.MaxLease}
}

// Enabled reports whether the mode can hold a lease.
func (p Policy) Enabled() bool { return p.Mode != config.FanNone && p.Mode != "" }

// DurationChoices are the lease lengths offered in the UI, in minutes: 15, 30, 60, 120
// up to MaxLease, plus MaxLease itself when it is not one of them.
func (p Policy) DurationChoices() []int {
	maxMin := int(p.MaxLease / time.Minute)
	var out []int
	for _, m := range []int{15, 30, 60, 120} {
		if m <= maxMin {
			out = append(out, m)
		}
	}
	if (len(out) == 0 || out[len(out)-1] != maxMin) && maxMin >= int(MinLease/time.Minute) {
		out = append(out, maxMin)
	}
	return out
}

// Request is a validated lease request: a floor in percent (already ≥ SafeMin) and a
// duration in [MinLease, MaxLease].
type Request struct {
	Pct      int
	Duration time.Duration
}

// ParseRequest validates form values strictly (rule 3: validated integers clamped to the
// floor). pct must be 0–100 and is raised to the safe minimum; minutes must be within
// [MinLease, MaxLease].
func ParseRequest(pct, minutes string, p Policy) (Request, error) {
	if !p.Enabled() {
		return Request{}, ErrNotConfigured
	}
	if !pctPattern.MatchString(pct) || !minutesPattern.MatchString(minutes) {
		return Request{}, fmt.Errorf("%w: enter whole numbers", ErrInvalid)
	}
	v, _ := strconv.Atoi(pct) // ≤ 3 digits: cannot fail
	m, _ := strconv.Atoi(minutes)
	if v > 100 {
		return Request{}, fmt.Errorf("%w: the floor must be at most 100 %%", ErrInvalid)
	}
	d := time.Duration(m) * time.Minute
	if d < MinLease || d > p.MaxLease {
		return Request{}, fmt.Errorf("%w: the duration must be %d to %d minutes", ErrInvalid,
			int(MinLease/time.Minute), int(p.MaxLease/time.Minute))
	}
	return Request{Pct: max(v, p.SafeMin), Duration: d}, nil
}

package metrics

import "sync/atomic"

// Login stages counted by LoginCounter.
const (
	StagePassword = "password"
	StageTOTP     = "totp"
)

// LoginCounter counts failed sign-ins since start. The zero value is ready to use and
// safe for concurrent use; a nil *LoginCounter ignores calls.
type LoginCounter struct {
	password, totp, other atomic.Uint64
}

// Failure records one failed attempt at stage (unknown stages count as "other").
func (c *LoginCounter) Failure(stage string) {
	if c == nil {
		return
	}
	switch stage {
	case StagePassword:
		c.password.Add(1)
	case StageTOTP:
		c.totp.Add(1)
	default:
		c.other.Add(1)
	}
}

// stageCount is one oob_login_failures_total series.
type stageCount struct {
	stage string
	n     uint64
}

// counts returns the per-stage counts in a fixed order.
func (c *LoginCounter) counts() []stageCount {
	return []stageCount{{StagePassword, c.password.Load()}, {StageTOTP, c.totp.Load()}, {"other", c.other.Load()}}
}

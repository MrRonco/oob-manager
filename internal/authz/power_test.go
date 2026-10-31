package authz

import (
	"errors"
	"testing"
)

// TestPowerMatrix is the P2 rule spelled out: safe power actions need operator or admin
// with a fresh step-up, forced ones admin with a fresh step-up (the typed server name is
// enforced by the UI), and API tokens never reach any of them, whatever their role.
func TestPowerMatrix(t *testing.T) {
	safe := []Action{PowerOn, PowerGracefulStop, PowerGracefulRestart}
	forced := []Action{PowerForceOff, PowerCycle, PowerForceRestart}
	roles := []Role{RoleViewer, RoleOperator, RoleAdmin}
	for _, kind := range []Kind{KindSession, KindToken} {
		for _, role := range roles {
			for _, fresh := range []bool{false, true} {
				p := Principal{Kind: kind, Role: role}
				for _, a := range append(append([]Action{}, safe...), forced...) {
					isForced := a == PowerForceOff || a == PowerCycle || a == PowerForceRestart
					var want error
					switch {
					case kind == KindToken, role == RoleViewer, isForced && role != RoleAdmin:
						want = ErrForbidden
					case !fresh:
						want = ErrStepUpRequired
					}
					if got := Authorize(p, a, fresh); !errors.Is(got, want) || (want == nil && got != nil) {
						t.Errorf("%s %s fresh=%v %s: got %v, want %v", kind, role, fresh, a, got, want)
					}
				}
			}
		}
	}
}

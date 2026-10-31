package redfish

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"oob-manager/internal/bmc"
)

// Power control (P2): the fourth POST exception of the transport allowlist
// (security.md §3a). A Resetter is a short-lived driver with the operator login whose
// action policy accepts exactly one URI shape, the standard ComputerSystem.Reset action,
// and whose only body is {"ResetType": <one of resetTypes>}.

// resetActionPattern is the only POST target a Resetter's driver may use.
var resetActionPattern = regexp.MustCompile(`^/redfish/v1/Systems/[A-Za-z0-9._-]{1,64}/Actions/ComputerSystem\.Reset$`)

// resetTypes is the closed set of ResetType values this app ever sends. Nmi,
// PushPowerButton and vendor values are never sent, even when a BMC offers them.
var resetTypes = []string{"On", "GracefulShutdown", "GracefulRestart", "ForceOff", "PowerCycle", "ForceRestart"}

const resetLogoutTimeout = 10 * time.Second

// IsResetActionURI reports whether p is exactly a ComputerSystem.Reset action URI.
func IsResetActionURI(p string) bool {
	return resetActionPattern.MatchString(p) && !strings.Contains(p, "..")
}

// Resetter sends ComputerSystem.Reset to one BMC and reads the host power state.
type Resetter struct {
	d       *Driver
	system  string
	target  string
	allowed []string
}

type resetSystemDoc struct {
	PowerState string `json:"PowerState"`
	Actions    struct {
		Reset struct {
			Target    string   `json:"target"`
			Allowable []string `json:"ResetType@Redfish.AllowableValues"`
		} `json:"#ComputerSystem.Reset"`
	} `json:"Actions"`
}

// resetBody is the whole request body: {"ResetType":"<type>"}, nothing else.
type resetBody struct {
	ResetType string `json:"ResetType"`
}

// OpenResetter logs in with cfg (the operator account) and finds the first system's
// Reset action. The target must be that system's own action URI; otherwise, or when the
// system offers no Reset, it returns ErrUnsupported. The caller must Close it.
func OpenResetter(ctx context.Context, cfg Config) (*Resetter, error) {
	d, err := New(cfg, WithActionPolicy(IsResetActionURI))
	if err != nil {
		return nil, err
	}
	r, err := discoverReset(ctx, d)
	if err != nil {
		closeQuietly(ctx, d)
		return nil, err
	}
	return r, nil
}

func discoverReset(ctx context.Context, d *Driver) (*Resetter, error) {
	var root rootDoc
	if err := d.GetJSON(ctx, serviceRoot, &root); err != nil {
		return nil, err
	}
	sys, err := d.firstMember(ctx, root.Systems.ID)
	if err != nil {
		return nil, err
	}
	if sys == "" {
		return nil, fmt.Errorf("reset: %w: no ComputerSystem", bmc.ErrUnsupported)
	}
	var doc resetSystemDoc
	if err := d.GetJSON(ctx, sys, &doc); err != nil {
		return nil, err
	}
	target := doc.Actions.Reset.Target
	if target != sys+"/Actions/ComputerSystem.Reset" || !IsResetActionURI(target) {
		return nil, fmt.Errorf("reset: %w: no usable ComputerSystem.Reset action", bmc.ErrUnsupported)
	}
	return &Resetter{d: d, system: sys, target: target, allowed: slices.Clone(doc.Actions.Reset.Allowable)}, nil
}

func closeQuietly(ctx context.Context, d *Driver) {
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), resetLogoutTimeout)
	defer cancel()
	_ = d.Close(lctx)
}

// Allowed returns the ResetType values the BMC advertises (a copy).
func (r *Resetter) Allowed() []string { return slices.Clone(r.allowed) }

// PowerState reads the host power state now.
func (r *Resetter) PowerState(ctx context.Context) (bmc.PowerState, error) {
	var doc resetSystemDoc
	if err := r.d.GetJSON(ctx, r.system, &doc); err != nil {
		return bmc.PowerUnknown, err
	}
	return bmc.ParsePowerState(doc.PowerState), nil
}

// Reset POSTs {"ResetType": resetType} to the system's Reset action. resetType must be
// in the closed set and advertised by the BMC; otherwise ErrUnsupported and nothing is
// sent. A 401 is not retried (resets are not idempotent).
func (r *Resetter) Reset(ctx context.Context, resetType string) error {
	if !slices.Contains(resetTypes, resetType) || !slices.Contains(r.allowed, resetType) {
		return fmt.Errorf("reset %q: %w", resetType, bmc.ErrUnsupported)
	}
	return r.d.PostAction(ctx, r.target, resetBody{ResetType: resetType}, nil)
}

// Close logs out (bounded, also when ctx is already cancelled).
func (r *Resetter) Close(ctx context.Context) error {
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), resetLogoutTimeout)
	defer cancel()
	if err := r.d.Close(lctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

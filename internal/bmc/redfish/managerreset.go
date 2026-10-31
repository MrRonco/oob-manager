package redfish

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"oob-manager/internal/bmc"
)

// BMC restart (tech_doc §37): the sixth exception of the transport allowlist
// (security.md §3a). A ManagerResetter is a short-lived driver with the operator login
// whose action policy accepts exactly one URI shape, the standard Manager.Reset action,
// and whose only body is {"ResetType":"GracefulRestart"}. Manager.ResetToDefaults, the
// Dell OEM ResetToDefaults and SetCustomDefaults never match the policy.

// managerResetPattern is the only POST target a ManagerResetter's driver may use.
var managerResetPattern = regexp.MustCompile(`^/redfish/v1/Managers/[A-Za-z0-9._-]{1,64}/Actions/Manager\.Reset$`)

// ManagerResetType is the one ResetType this app ever sends to a Manager. ForceRestart
// is never sent, even when a BMC offers it.
const ManagerResetType = "GracefulRestart"

// IsManagerResetActionURI reports whether p is exactly a Manager.Reset action URI.
func IsManagerResetActionURI(p string) bool {
	return managerResetPattern.MatchString(p) && !strings.Contains(p, "..")
}

// managerResetOffered: the manager's own Reset action, advertising GracefulRestart.
func managerResetOffered(managerURI string, a managerResetAction) bool {
	return managerURI != "" && a.Target == managerURI+"/Actions/Manager.Reset" &&
		IsManagerResetActionURI(a.Target) && slices.Contains(a.Allowable, ManagerResetType)
}

// parseLastReset reads LastResetTime (RFC 3339); zero when absent or unreadable.
func parseLastReset(raw string) time.Time {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(raw))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// managerResetBody is the whole request body: {"ResetType":"GracefulRestart"}.
type managerResetBody struct {
	ResetType string `json:"ResetType"`
}

// ManagerResetter sends Manager.Reset (GracefulRestart) to one BMC.
type ManagerResetter struct {
	d      *Driver
	target string
}

// OpenManagerResetter logs in with cfg (the operator account) and finds the Manager
// that manages the first system (Links.ManagedBy, else the first Manager, as the probe
// does). The advertised target must be that manager's own Reset action URI and list
// GracefulRestart; otherwise it returns ErrUnsupported. The caller must Close it.
func OpenManagerResetter(ctx context.Context, cfg Config) (*ManagerResetter, error) {
	d, err := New(cfg, WithActionPolicy(IsManagerResetActionURI))
	if err != nil {
		return nil, err
	}
	target, err := discoverManagerReset(ctx, d)
	if err != nil {
		closeQuietly(ctx, d)
		return nil, err
	}
	return &ManagerResetter{d: d, target: target}, nil
}

func discoverManagerReset(ctx context.Context, d *Driver) (string, error) {
	var root rootDoc
	if err := d.GetJSON(ctx, serviceRoot, &root); err != nil {
		return "", err
	}
	sysURI, err := d.firstMember(ctx, root.Systems.ID)
	if err != nil {
		return "", err
	}
	var sys systemLinksDoc
	if sysURI != "" {
		if err = d.GetJSON(ctx, sysURI, &sys); err != nil {
			return "", err
		}
	}
	mgrURI, err := d.linkOrFirst(ctx, sys.Links.ManagedBy, root.Managers.ID)
	if err != nil {
		return "", err
	}
	if mgrURI == "" {
		return "", fmt.Errorf("manager reset: %w: no Manager", bmc.ErrUnsupported)
	}
	body, err := d.get(ctx, mgrURI)
	if err != nil {
		return "", err
	}
	reset, _ := managerExtras(body)
	if !managerResetOffered(mgrURI, reset) {
		return "", fmt.Errorf("manager reset: %w: no usable Manager.Reset action", bmc.ErrUnsupported)
	}
	return reset.Target, nil
}

// managerExtras reads #Manager.Reset and LastResetTime from a Manager document
// leniently (review S-M2): a field of the wrong type reads as absent ("not offered",
// "unknown") instead of failing the decode, which would break discovery and polling.
func managerExtras(body []byte) (managerResetAction, string) {
	var top struct {
		LastResetTime json.RawMessage `json:"LastResetTime"`
		Actions       json.RawMessage `json:"Actions"`
	}
	if json.Unmarshal(body, &top) != nil {
		return managerResetAction{}, ""
	}
	var last string
	if json.Unmarshal(top.LastResetTime, &last) != nil {
		last = ""
	}
	var actions map[string]json.RawMessage
	if json.Unmarshal(top.Actions, &actions) != nil {
		return managerResetAction{}, last
	}
	var raw struct {
		Target    json.RawMessage `json:"target"`
		Allowable json.RawMessage `json:"ResetType@Redfish.AllowableValues"`
	}
	var a managerResetAction
	if json.Unmarshal(actions["#Manager.Reset"], &raw) != nil ||
		json.Unmarshal(raw.Target, &a.Target) != nil || json.Unmarshal(raw.Allowable, &a.Allowable) != nil {
		return managerResetAction{}, last
	}
	return a, last
}

// withoutManagerExtras removes Actions and LastResetTime before the typed decode of a
// Manager, so their shape can never fail it (the typed Manager does not use them).
func withoutManagerExtras(body []byte) []byte {
	var doc map[string]json.RawMessage
	if json.Unmarshal(body, &doc) != nil {
		return body
	}
	delete(doc, "Actions")
	delete(doc, "LastResetTime")
	out, err := json.Marshal(doc)
	if err != nil {
		return body
	}
	return out
}

// Target is the Manager.Reset URI the resetter posts to.
func (r *ManagerResetter) Target() string { return r.target }

// Reset POSTs {"ResetType":"GracefulRestart"} to the manager's Reset action, once. A 401
// is not retried (a reset is not idempotent); a 403 is ErrPrivilege (and ErrAuth): the
// operator account lacks the privilege.
func (r *ManagerResetter) Reset(ctx context.Context) error {
	err := r.d.PostAction(ctx, r.target, managerResetBody{ResetType: ManagerResetType}, nil)
	if isStatus(err, http.StatusForbidden) {
		return fmt.Errorf("%w: %w", bmc.ErrPrivilege, err)
	}
	return err
}

// Close logs out, bounded. After a reset the BMC is usually going away, so a logout that
// cannot reach it (unreachable, timeout, a 5xx while it restarts) is not an error.
func (r *ManagerResetter) Close(ctx context.Context) error {
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), resetLogoutTimeout)
	defer cancel()
	err := r.d.Close(lctx)
	var se *statusError
	switch {
	case err == nil, errors.Is(err, context.Canceled), errors.Is(err, bmc.ErrUnreachable),
		errors.Is(err, bmc.ErrTimeout), errors.As(err, &se) && se.code >= http.StatusInternalServerError:
		return nil
	default:
		return err
	}
}

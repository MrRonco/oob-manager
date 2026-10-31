package dellredfish

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfish"
	"oob-manager/internal/secrets"
)

// KVM launch: iDRAC9's DelliDRACCardService.GetKVMSession returns a single-use
// temporary user/password pair for its HTML5 console (docs/system_design.md §5.2).
const (
	kvmActionKey = "#DelliDRACCardService.GetKVMSession"
	// KVMSessionType is sent as SessionTypeName. Dell's sample script passes a file
	// name here; the value is not otherwise documented (verify in the P5.1 spike).
	KVMSessionType = "oob-manager"
	maxTempLen     = 128
	logoutTimeout  = 10 * time.Second
)

// kvmActionPattern is the only POST target the launcher's driver may use: the action on
// the iDRAC card service, under the manager's Oem/Dell links (iDRAC9 4.x+) or the older
// /redfish/v1/Dell/Managers/<id> tree.
var kvmActionPattern = regexp.MustCompile(`^/redfish/v1/(Managers/[A-Za-z0-9.]{1,64}/Oem/Dell|Dell/Managers/[A-Za-z0-9.]{1,64})/DelliDRACCardService/Actions/DelliDRACCardService\.GetKVMSession$`)

// IsKVMActionURI reports whether p is exactly a GetKVMSession action URI.
func IsKVMActionURI(p string) bool {
	return kvmActionPattern.MatchString(p) && !strings.Contains(p, "..")
}

type managerOemLinks struct {
	Links struct {
		Oem struct {
			Dell struct {
				DelliDRACCardService struct {
					ID string `json:"@odata.id"`
				} `json:"DelliDRACCardService"`
			} `json:"Dell"`
		} `json:"Oem"`
	} `json:"Links"`
}

type cardServiceDoc struct {
	Actions map[string]struct {
		Target string `json:"target"`
	} `json:"Actions"`
}

// getter is what kvmTarget needs from a Redfish driver.
type getter interface {
	GetJSON(ctx context.Context, uri string, v any) error
}

// kvmTarget returns the GetKVMSession target offered under managerURI, or "" when the
// BMC does not offer it. The target must sit under the card service it came from and
// match IsKVMActionURI.
func kvmTarget(ctx context.Context, d getter, managerURI string) (string, error) {
	if managerURI == "" {
		return "", nil
	}
	var mgr managerOemLinks
	if err := d.GetJSON(ctx, managerURI, &mgr); err != nil {
		return "", absentIsEmpty(err)
	}
	svc := mgr.Links.Oem.Dell.DelliDRACCardService.ID
	if svc == "" {
		svc = managerURI + "/Oem/Dell/DelliDRACCardService"
	}
	var doc cardServiceDoc
	if err := d.GetJSON(ctx, svc, &doc); err != nil {
		return "", absentIsEmpty(err)
	}
	target := doc.Actions[kvmActionKey].Target
	if !IsKVMActionURI(target) || !strings.HasPrefix(target, svc+"/Actions/") {
		return "", nil
	}
	return target, nil
}

func absentIsEmpty(err error) error {
	if errors.Is(err, bmc.ErrNotFound) {
		return nil
	}
	return err
}

// Probe delegates to the generic driver and adds KVMLaunch. Detection uses GETs only;
// a failed detection leaves the flag off instead of failing the probe.
func (d *Driver) Probe(ctx context.Context) (bmc.Capabilities, error) {
	caps, err := d.base.Probe(ctx)
	if err != nil {
		return caps, err
	}
	res, err := d.base.Resources(ctx)
	if err != nil {
		return caps, nil
	}
	target, _ := kvmTarget(ctx, d.base, res.Manager)
	f := caps.Flags()
	f.KVMLaunch = target != ""
	return bmc.NewCapabilities(bmc.CapabilityParams{Flags: f, ResetTypes: caps.ResetTypes()}), nil
}

// LaunchKVM logs in with the operator account in cfg, asks the iDRAC for a one-time
// console credential and logs out again. It returns the launch URL
// https://<host>/console?username=…&tempUsername=…&tempPassword=… as a Secret: it holds
// a (single-use, short-lived) credential and must never be logged.
func LaunchKVM(ctx context.Context, cfg redfish.Config, host string) (secrets.Secret, error) {
	if host == "" {
		return secrets.Secret{}, fmt.Errorf("%w: console host is required", bmc.ErrInvalidConfig)
	}
	user := cfg.Username
	d, err := redfish.New(cfg, redfish.WithActionPolicy(IsKVMActionURI))
	if err != nil {
		return secrets.Secret{}, err
	}
	defer func() {
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), logoutTimeout)
		defer cancel()
		_ = d.Close(lctx)
	}()
	target, err := launcherTarget(ctx, d)
	if err != nil {
		return secrets.Secret{}, err
	}
	var out struct{ TempUsername, TempPassword string }
	if err := d.PostAction(ctx, target, map[string]string{"SessionTypeName": KVMSessionType}, &out); err != nil {
		return secrets.Secret{}, err
	}
	if !validTemp(out.TempUsername) || !validTemp(out.TempPassword) {
		return secrets.Secret{}, fmt.Errorf("GetKVMSession: %w: unusable temporary credential", bmc.ErrDecode)
	}
	q := url.Values{"username": {user}, "tempUsername": {out.TempUsername}, "tempPassword": {out.TempPassword}}
	u := url.URL{Scheme: "https", Host: host, Path: "/console", RawQuery: q.Encode()}
	return secrets.New(u.String()), nil
}

// launcherTarget finds the action with a minimal walk (service root → first manager).
func launcherTarget(ctx context.Context, d *redfish.Driver) (string, error) {
	var root struct {
		Managers struct {
			ID string `json:"@odata.id"`
		} `json:"Managers"`
	}
	if err := d.GetJSON(ctx, "/redfish/v1", &root); err != nil {
		return "", err
	}
	members, err := d.Members(ctx, root.Managers.ID)
	if err != nil {
		return "", err
	}
	if len(members) == 0 {
		return "", fmt.Errorf("GetKVMSession: %w: no manager", bmc.ErrUnsupported)
	}
	target, err := kvmTarget(ctx, d, members[0])
	if err != nil {
		return "", err
	}
	if target == "" {
		return "", fmt.Errorf("GetKVMSession: %w", bmc.ErrUnsupported)
	}
	return target, nil
}

func validTemp(s string) bool {
	if s == "" || len(s) > maxTempLen {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r > '~' {
			return false
		}
	}
	return true
}

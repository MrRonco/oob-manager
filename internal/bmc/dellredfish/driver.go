package dellredfish

import (
	"context"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfish"
	"oob-manager/internal/secrets"
)

// Driver is the generic Redfish driver plus Dell iDRAC knowledge: the iDRAC8 legacy
// SEL/Lifecycle paths, firmware versions from Dell inventory IDs and the licence tier.
// It is read-only and safe for concurrent use.
type Driver struct {
	base *redfish.Driver
}

// New builds a Dell driver. Extra options (e.g. redfish.WithClock) are applied first;
// the Dell options always win.
func New(cfg redfish.Config, opts ...redfish.Option) (*Driver, error) {
	all := append(append([]redfish.Option(nil), opts...),
		redfish.WithSELFallbacks(legacySELPaths),
		redfish.WithFirmwareParser(parseFirmwareMembers),
	)
	base, err := redfish.New(cfg, all...)
	if err != nil {
		return nil, err
	}
	return &Driver{base: base}, nil
}

// Snapshot delegates to the generic driver.
func (d *Driver) Snapshot(ctx context.Context) (bmc.Snapshot, error) { return d.base.Snapshot(ctx) }

// EventLog reads the SEL; on iDRAC8 this is Managers/<id>/Logs/Sel.
func (d *Driver) EventLog(ctx context.Context, since time.Time) (bmc.EventLog, error) {
	return d.base.EventLog(ctx, since)
}

// Inventory is the generic inventory with Dell firmware parsing and the licence attached.
func (d *Driver) Inventory(ctx context.Context) (bmc.Inventory, error) {
	inv, err := d.base.Inventory(ctx)
	if err != nil {
		return bmc.Inventory{}, err
	}
	lic, err := d.License(ctx)
	if err != nil {
		return bmc.Inventory{}, err
	}
	return inv.WithLicense(lic), nil
}

// legacySELPaths is where iDRAC8 (13G) serves SEL entries; it has no LogServices/Sel/Entries.
func legacySELPaths(manager string) []string { return []string{manager + "/Logs/Sel"} }

// Close deletes the Redfish session (if any); see redfish.Driver.Close.
func (d *Driver) Close(ctx context.Context) error { return d.base.Close(ctx) }

// SetCredentials replaces the login and deletes the old session; see redfish.Driver.
func (d *Driver) SetCredentials(ctx context.Context, username string, password secrets.Secret) error {
	return d.base.SetCredentials(ctx, username, password)
}

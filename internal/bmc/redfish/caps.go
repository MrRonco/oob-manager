package redfish

import (
	"slices"
	"time"

	"github.com/stmcginnis/gofish/schemas"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/textclean"
)

func capabilityFlags(root rootDoc, res Resources, mgr schemas.Manager, now time.Time) bmc.CapabilityFlags {
	return bmc.CapabilityFlags{
		RedfishVersion:    clean(root.RedfishVersion),
		Product:           clean(root.Product),
		BMCModel:          clean(mgr.Model),
		BMCFirmware:       clean(mgr.FirmwareVersion),
		LegacyThermal:     res.Thermal != "",
		ThermalSubsystem:  res.ThermalSubsystem != "",
		LegacyPower:       res.Power != "",
		PowerSubsystem:    res.PowerSubsystem != "",
		SEL:               res.SELEntries != "",
		SELSource:         res.SELEntries,
		LicenseService:    res.LicenseService != "",
		FirmwareInventory: res.FirmwareInventory != "",
		GraphicalConsole:  mgr.GraphicalConsole.ServiceEnabled && len(mgr.GraphicalConsole.ConnectTypesSupported) > 0,
		SerialConsole:     mgr.SerialConsole.ServiceEnabled, //nolint:staticcheck // SA1019: iDRAC8/9 report the serial console only on the Manager
		SSH: mgr.CommandShell.ServiceEnabled &&
			slices.Contains(mgr.CommandShell.ConnectTypesSupported, schemas.SSHCommandConnectTypesSupported),
		ProbedAt: now,
	}
}

const maxFieldLen = 1024

// clean sanitizes a BMC-supplied string (textclean: invalid UTF-8, control and format
// characters out), trims BMC padding (Dell pads models with spaces; the R240 reports
// " ") and bounds its length.
func clean(s string) string { return textclean.Clean(s, maxFieldLen) }

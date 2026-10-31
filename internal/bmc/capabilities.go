package bmc

import (
	"slices"
	"time"
)

// CapabilityFlags are the scalar results of a probe. A false flag means "not offered by
// this BMC" (endpoint absent), never "probe failed".
type CapabilityFlags struct {
	RedfishVersion string
	Product        string
	BMCModel       string
	BMCFirmware    string

	LegacyThermal    bool // Chassis/{id}/Thermal (deprecated schema; iDRAC8 has only this)
	ThermalSubsystem bool // Chassis/{id}/ThermalSubsystem (iDRAC9)
	LegacyPower      bool // Chassis/{id}/Power
	PowerSubsystem   bool // Chassis/{id}/PowerSubsystem

	SEL       bool
	SELSource string // URI of the SEL entries collection that answered

	LicenseService    bool
	FirmwareInventory bool

	GraphicalConsole bool // Manager.GraphicalConsole.ServiceEnabled
	SerialConsole    bool // Manager.SerialConsole.ServiceEnabled
	SSH              bool // Manager.CommandShell offers SSH and is enabled
	// KVMLaunch: the Dell iDRAC9 DelliDRACCardService offers GetKVMSession (one-time
	// native console launch). Detected with read-only GETs; false when not offered.
	KVMLaunch bool
	// ManagerReset: the Manager offers #Manager.Reset at its own action URI
	// (<manager>/Actions/Manager.Reset) and lists GracefulRestart (BMC restart, tech_doc §37).
	ManagerReset bool
	// BMCLastReset is the Manager's LastResetTime (iDRAC9 reports it, iDRAC8 does not);
	// zero when not reported or unreadable.
	BMCLastReset time.Time

	ProbedAt time.Time
}

// CapabilityParams are the inputs to NewCapabilities.
type CapabilityParams struct {
	Flags      CapabilityFlags
	ResetTypes []string // ComputerSystem.Reset AllowableValues (read only in this phase)
	// ManagerResetTypes is Manager.Reset's ResetType@Redfish.AllowableValues (read only).
	ManagerResetTypes []string
}

// Capabilities is an immutable probe result.
type Capabilities struct {
	flags             CapabilityFlags
	resetTypes        []string
	managerResetTypes []string
}

// NewCapabilities copies its inputs.
func NewCapabilities(p CapabilityParams) Capabilities {
	return Capabilities{flags: p.Flags, resetTypes: slices.Clone(p.ResetTypes),
		managerResetTypes: slices.Clone(p.ManagerResetTypes)}
}

// Flags returns the scalar capability flags.
func (c Capabilities) Flags() CapabilityFlags { return c.flags }

// ResetTypes returns a copy of the advertised reset types.
func (c Capabilities) ResetTypes() []string { return slices.Clone(c.resetTypes) }

// ManagerResetTypes returns a copy of the BMC restart types the Manager advertises.
func (c Capabilities) ManagerResetTypes() []string { return slices.Clone(c.managerResetTypes) }

package metrics

import (
	"context"
	"sync/atomic"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
)

var t0 = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

// staticFleet is a fleet.Reader over fixed states that counts reads.
type staticFleet struct {
	states []fleet.ServerState
	reads  *atomic.Int64
}

func (f staticFleet) Servers() []fleet.ServerState {
	if f.reads != nil {
		f.reads.Add(1)
	}
	return append([]fleet.ServerState(nil), f.states...)
}

func (f staticFleet) Server(id string) (fleet.ServerState, bool) {
	for _, s := range f.states {
		if s.ID == id {
			return s, true
		}
	}
	return fleet.ServerState{}, false
}

func (f staticFleet) Polled() bool { return true }

type fakeShipper struct{}

func (fakeShipper) Stats() audit.ShipperStats {
	return audit.ShipperStats{Active: true, Queued: 2, Dropped: 1, Connected: true, TLS: true, Reconnects: 1,
		LastSuccess: t0.Add(-5 * time.Second)}
}

func r(v float64) bmc.Reading { return bmc.ReadingOf(v) }

func healthySnapshot() bmc.Snapshot {
	return bmc.NewSnapshot(bmc.SnapshotParams{
		TakenAt: t0.Add(-30 * time.Second), PowerState: bmc.PowerOn, Health: bmc.HealthOK,
		Temperatures: []bmc.Temperature{
			{ID: "inlet", Name: "System Board Inlet Temp", Context: "Intake", Celsius: r(22), WarnAbove: r(42), CritAbove: r(47), Health: bmc.HealthOK},
			{ID: "cpu1", Name: "CPU1 Temp", Context: "CPU", Celsius: r(55.5), Health: bmc.HealthWarning},
			{ID: "null", Name: "No reading", Context: "CPU", Celsius: bmc.NoReading(), Health: bmc.HealthUnknown},
		},
		Fans: []bmc.Fan{
			{ID: "fan1", Name: "Fan1A", Speed: r(7440), Units: bmc.FanRPM, Health: bmc.HealthOK},
			{ID: "fan2", Name: "Fan2", Speed: r(35), Units: bmc.FanPercent, Health: bmc.HealthOK},
		},
		PSUs: []bmc.PSU{
			{ID: "psu1", Name: "PS1 Status", InputWatts: r(120), Health: bmc.HealthOK},
			{ID: "psu2", Name: "PS2 Status", Health: bmc.HealthCritical},
		},
		Power:          bmc.PowerDraw{ConsumedWatts: r(241)},
		Voltages:       []bmc.Voltage{{ID: "v1", Name: "CPU1 VCORE PG", Health: bmc.HealthOK}, {ID: "v2", Name: "PS1 Voltage 1", Volts: r(230), Health: bmc.HealthOK}},
		PowerTelemetry: bmc.PowerTelemetryAvailable,
	})
}

func healthyState() fleet.ServerState {
	inv := bmc.NewInventory(bmc.InventoryParams{InventoryInfo: bmc.InventoryInfo{Model: "PowerEdge R730xd",
		SerialNumber: "SERIAL-1", SKU: "TAG1", BIOSVersion: "2.19.0", BMCFirmware: "2.86"},
		License: bmc.License{Tier: bmc.LicenseEnterprise}})
	return fleet.ServerState{
		ID: "storage", Name: "Storage node", Snapshot: healthySnapshot(), HasSnapshot: true,
		SEL: bmc.NewEventLog("sel", []bmc.Event{{ID: "1", Severity: bmc.SeverityOK}, {ID: "2", Created: t0.Add(-time.Hour),
			Severity: bmc.SeverityCritical}, {ID: "3", Severity: bmc.SeverityCritical}}, true), HasSEL: true,
		Lifecycle: bmc.NewEventLog("lifecycle", []bmc.Event{{ID: "L1", Severity: bmc.SeverityWarning},
			{ID: "L2", Severity: bmc.SeverityWarning}}, true), HasLifecycle: true,
		Inventory: inv, HasInventory: true,
		Capabilities:    bmc.NewCapabilities(bmc.CapabilityParams{Flags: bmc.CapabilityFlags{BMCLastReset: t0.Add(-48 * time.Hour)}}),
		HasCapabilities: true,
		LastAttempt:     t0.Add(-30 * time.Second), LastSuccess: t0.Add(-30 * time.Second), LastPollDuration: 1500 * time.Millisecond,
	}
}

func staleState() fleet.ServerState {
	return fleet.ServerState{ID: "edge", Name: "Edge node", Snapshot: healthySnapshot(), HasSnapshot: true,
		LastAttempt: t0, LastSuccess: t0.Add(-10 * time.Minute), LastPollDuration: 2 * time.Second,
		ConsecutiveFailures: 4, Stale: true, Restarting: true}
}

func neverPolled() fleet.ServerState {
	return fleet.ServerState{ID: "new", Name: "New \"box\"\nline2", Stale: true}
}

func fullConfig(f fleet.Reader) Config {
	logins := &LoginCounter{}
	logins.Failure(StagePassword)
	logins.Failure(StagePassword)
	logins.Failure(StageTOTP)
	return Config{
		Fleet: f,
		FanStatus: func(_ context.Context, id string) (FanState, bool) {
			if id != "storage" {
				return FanState{}, false
			}
			return FanState{LeaseActive: true, LeasePct: 45, Remaining: 15 * time.Minute, AppliedPct: 45, HasApplied: true}, true
		},
		ConsoleActive: func(id string) (bool, bool) { return id == "storage", id == "edge" },
		NotifyTargets: func() []NotifyTarget {
			return []NotifyTarget{{ID: "phone", Enabled: true, Sent: 5}, {ID: "mail", Enabled: true, Failing: true,
				ConsecutiveFailures: 3, Dropped: 2}, {ID: "off", Enabled: false}}
		},
		Shipper:      fakeShipper{},
		AuditChainOK: func() bool { return true },
		Logins:       logins,
		Maintenance: func(id string) MaintenanceState {
			switch id {
			case "edge":
				return MaintenanceState{Active: true, Until: t0.Add(2 * time.Hour)}
			case "new":
				return MaintenanceState{Active: true} // until ended
			}
			return MaintenanceState{}
		},
		// SEL entry 2 (with its BMC timestamp) and lifecycle L1 are acknowledged.
		Acked: func(server, log, id string, created time.Time) bool {
			return server == "storage" && ((log == "sel" && id == "2" && created.Equal(t0.Add(-time.Hour))) ||
				(log == "lifecycle" && id == "L1"))
		},
		BMCReset: func(id string) BMCResetState {
			if id != "edge" {
				return BMCResetState{}
			}
			return BMCResetState{LastVerified: t0.Add(-time.Hour),
				Counts: map[string]int64{"sent": 2, "verified": 1, "refused": 1}}
		},
		Firmware: func(id string) (FirmwareCounts, bool) {
			if id != "storage" {
				return FirmwareCounts{}, false
			}
			return FirmwareCounts{Components: 15, Flagged: map[string]int{"below_minimum": 1, "not_applied": 1, "update_urgent": 1},
				Updates: map[string]int{"urgent": 1, "recommended": 2}, LastScan: t0.Add(-time.Hour), Changes: 2}, true
		},
		Catalog: func() CatalogState {
			return CatalogState{Source: "dell", Published: t0.Add(-7 * 24 * time.Hour), LastCheck: t0.Add(-time.Hour),
				LastResult: "not_modified", Failures: map[string]int64{"download": 1}}
		},
		History: func() HistoryState {
			return HistoryState{Ready: true, RawRows: 161280, HourlyRows: 2880, DailyRows: 120, DBBytes: 9 << 20,
				FreelistPages: 12, HourlyDone: t0.Truncate(time.Hour), DailyDone: t0.Truncate(24 * time.Hour),
				PruneTook: 1500 * time.Millisecond}
		},
		Build:     BuildInfo{Version: "v0.6.0", Commit: "abc123", GoVersion: "go1.27.3"},
		StartTime: t0.Add(-time.Hour),
		Now:       func() time.Time { return t0 },
		Runtime:   func() RuntimeStats { return RuntimeStats{Goroutines: 42, HeapAlloc: 1 << 20, Sys: 8 << 20, NumGC: 7} },
	}
}

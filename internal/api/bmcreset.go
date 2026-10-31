package api

import (
	"time"

	"oob-manager/internal/fleet"
)

// BMCResetRecord is the app's last BMC restart of a server (bmcreset.Service).
type BMCResetRecord struct {
	At         time.Time
	By, Result string
}

// bmcJSON is a server's BMC restart state (tech_doc §37). restarting mirrors the
// summary's bmc_restarting; stale keeps its honest value meanwhile.
type bmcJSON struct {
	ResetSupported     bool          `json:"reset_supported"`
	Restarting         bool          `json:"restarting"`
	RestartRequestedAt *time.Time    `json:"restart_requested_at"`
	RestartDeadline    *time.Time    `json:"restart_deadline"`
	LastResetTime      *time.Time    `json:"last_reset_time"`
	LastAppReset       *appResetJSON `json:"last_app_reset"`
}

type appResetJSON struct {
	At     time.Time `json:"at"`
	By     string    `json:"by"`
	Result string    `json:"result"`
}

// bmcOf builds the bmc object: the BMC's own facts from the fleet, the app's last
// restart from the BMC reset service (when wired).
func (a *API) bmcOf(s fleet.ServerState) bmcJSON {
	b := bmcJSON{Restarting: s.Restarting}
	if s.HasCapabilities {
		f := s.Capabilities.Flags()
		b.ResetSupported, b.LastResetTime = f.ManagerReset, timePtr(f.BMCLastReset)
	}
	if s.Restarting {
		b.RestartRequestedAt, b.RestartDeadline = timePtr(s.Restart.Since), timePtr(s.Restart.Until)
	}
	if a.deps.BMCReset != nil {
		if r, ok := a.deps.BMCReset(s.ID); ok {
			b.LastAppReset = &appResetJSON{At: r.At.UTC(), By: r.By, Result: r.Result}
		}
	}
	return b
}

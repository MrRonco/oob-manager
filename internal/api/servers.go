package api

import (
	"net/http"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
	"oob-manager/internal/web"
)

type serverSummary struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Tags        []string   `json:"tags"`
	Health      string     `json:"health"`
	PowerState  string     `json:"power_state"`
	LastPoll    *time.Time `json:"last_poll"`
	LastSuccess *time.Time `json:"last_success"`
	Stale       bool       `json:"stale"`
	Reachable   bool       `json:"reachable"`
	Breaker     string     `json:"breaker"`
	LastError   string     `json:"last_error,omitempty"`
	// UnreachableSince is when the current failure streak began (null when healthy).
	UnreachableSince *time.Time `json:"unreachable_since"`
	// Maintenance is the server's maintenance window, active or scheduled (null: none).
	Maintenance *maintenanceJSON `json:"maintenance"`
	// BMCRestarting: the app waits for the BMC to come back after a restart it requested
	// (stale stays honest meanwhile).
	BMCRestarting bool `json:"bmc_restarting"`
}

func summarize(s fleet.ServerState) serverSummary {
	health, power := string(bmc.HealthUnknown), string(bmc.PowerUnknown)
	if s.HasSnapshot {
		health, power = string(s.Snapshot.Health()), string(s.Snapshot.PowerState())
	}
	return serverSummary{
		ID: s.ID, Name: s.Name, Tags: orEmpty(s.Tags), Health: health, PowerState: power,
		LastPoll: timePtr(s.LastAttempt), LastSuccess: timePtr(s.LastSuccess),
		Stale: s.Stale, Reachable: s.Reachable(), Breaker: string(s.Breaker),
		LastError: string(s.LastError), UnreachableSince: timePtr(s.FailingSince), BMCRestarting: s.Restarting,
	}
}

func (a *API) listServers(w http.ResponseWriter, _ *http.Request) {
	all := a.deps.Fleet.Servers()
	out := make([]serverSummary, 0, len(all))
	for _, s := range all {
		sum := summarize(s)
		sum.Maintenance = a.maintenanceOf(s.ID)
		out = append(out, sum)
	}
	writeJSON(w, http.StatusOK, list[serverSummary]{Data: out, Meta: map[string]int{"total": len(out)}})
}

type temperatureJSON struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Context   string   `json:"context,omitempty"`
	Celsius   *float64 `json:"celsius"`
	WarnAbove *float64 `json:"warn_above"`
	CritAbove *float64 `json:"crit_above"`
	Health    string   `json:"health"`
}

type fanJSON struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Speed  *float64 `json:"speed"`
	Units  string   `json:"units"`
	Health string   `json:"health"`
}

type psuJSON struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Model          string   `json:"model,omitempty"`
	Firmware       string   `json:"firmware,omitempty"`
	CapacityWatts  *float64 `json:"capacity_watts"`
	InputWatts     *float64 `json:"input_watts"`
	OutputWatts    *float64 `json:"output_watts"`
	RatedInput     *float64 `json:"rated_input_watts"`
	LineInputVolts *float64 `json:"line_input_volts"`
	Health         string   `json:"health"`
}

type powerJSON struct {
	ConsumedWatts *float64 `json:"consumed_watts"`
	AverageWatts  *float64 `json:"average_watts"`
	MinWatts      *float64 `json:"min_watts"`
	MaxWatts      *float64 `json:"max_watts"`
	CapacityWatts *float64 `json:"capacity_watts"`
}

type voltageJSON struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Context string   `json:"context,omitempty"`
	Volts   *float64 `json:"volts"`
	Health  string   `json:"health"`
}

type serverDetail struct {
	serverSummary
	pollTiming
	TakenAt      *time.Time        `json:"taken_at"`
	Temperatures []temperatureJSON `json:"temperatures"`
	Fans         []fanJSON         `json:"fans"`
	PSUs         []psuJSON         `json:"psus"`
	Power        powerJSON         `json:"power"`
	// PowerTelemetry: "available", "unavailable" (the server reports no PSUs or draw at
	// all) or "unknown" (not read yet, or the read failed).
	PowerTelemetry string        `json:"power_telemetry"`
	Voltages       []voltageJSON `json:"voltages"`
	Problems       []string      `json:"problems"`
	// Acks are the acknowledged log entries of the server, newest first.
	Acks []ackJSON `json:"acks"`
	// BMC is the BMC restart state (tech_doc §37).
	BMC bmcJSON `json:"bmc"`
}

func (a *API) serverDetail(w http.ResponseWriter, r *http.Request) {
	s, ok := a.deps.Fleet.Server(r.PathValue("id"))
	if !ok {
		web.WriteProblem(w, r, http.StatusNotFound, "unknown server")
		return
	}
	d := detail(s)
	d.Maintenance, d.Acks, d.BMC = a.maintenanceOf(s.ID), a.acksOf(s.ID), a.bmcOf(s)
	writeJSON(w, http.StatusOK, d)
}

func detail(s fleet.ServerState) serverDetail {
	snap := s.Snapshot
	d := serverDetail{serverSummary: summarize(s), pollTiming: timingOf(s), Temperatures: []temperatureJSON{}, Fans: []fanJSON{},
		PSUs: []psuJSON{}, PowerTelemetry: string(snap.PowerTelemetry()), Voltages: voltagesJSON(snap.Voltages()),
		Problems: orEmpty(snap.Problems())}
	if !s.HasSnapshot {
		return d
	}
	d.TakenAt = timePtr(snap.TakenAt())
	for _, t := range snap.Temperatures() {
		d.Temperatures = append(d.Temperatures, temperatureJSON{ID: t.ID, Name: t.Name, Context: t.Context,
			Celsius: reading(t.Celsius), WarnAbove: reading(t.WarnAbove), CritAbove: reading(t.CritAbove),
			Health: string(t.Health)})
	}
	for _, f := range snap.Fans() {
		d.Fans = append(d.Fans, fanJSON{ID: f.ID, Name: f.Name, Speed: reading(f.Speed),
			Units: string(f.Units), Health: string(f.Health)})
	}
	for _, p := range snap.PSUs() {
		d.PSUs = append(d.PSUs, psuJSON{ID: p.ID, Name: p.Name, Model: p.Model, Firmware: p.Firmware,
			CapacityWatts: reading(p.CapacityWatts), InputWatts: reading(p.InputWatts),
			OutputWatts: reading(p.OutputWatts), RatedInput: reading(p.RatedInputWatts), LineInputVolts: reading(p.LineInputVolts), Health: string(p.Health)})
	}
	pw := snap.Power()
	d.Power = powerJSON{ConsumedWatts: reading(pw.ConsumedWatts), AverageWatts: reading(pw.AverageWatts),
		MinWatts: reading(pw.MinWatts), MaxWatts: reading(pw.MaxWatts), CapacityWatts: reading(pw.CapacityWatts)}
	return d
}

func voltagesJSON(vs []bmc.Voltage) []voltageJSON {
	out := make([]voltageJSON, 0, len(vs))
	for _, v := range vs {
		out = append(out, voltageJSON{ID: v.ID, Name: v.Name, Context: v.Context, Volts: reading(v.Volts),
			Health: string(v.Health)})
	}
	return out
}

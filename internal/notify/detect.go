package notify

import (
	"fmt"
	"slices"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
)

// DefaultDebounce is how long a changed health or PSU state must persist before it is
// reported (about two polls at the default 60 s interval), so one odd reading never
// pages anyone.
const DefaultDebounce = 90 * time.Second

// maxDetail caps the BMC text lines of one event.
const maxDetail = 5

// tracker debounces one signal of one server. The first observation is compared with
// a healthy baseline, so a problem present at startup is reported once.
type tracker struct {
	confirmed string
	candidate string
	since     time.Time
}

// observe returns the next tracker and, when v has held for debounce, the confirmed
// change (from, true).
func (tr tracker) observe(v string, now time.Time, debounce time.Duration) (tracker, string, bool) {
	if v == tr.confirmed {
		tr.candidate = ""
		return tr, "", false
	}
	if v != tr.candidate {
		tr.candidate, tr.since = v, now
	}
	if now.Sub(tr.since) < debounce {
		return tr, "", false
	}
	from := tr.confirmed
	tr.confirmed, tr.candidate = v, ""
	return tr, from, true
}

// logMark remembers which entries of one log were already seen.
type logMark struct {
	seen   map[string]bool
	newest time.Time
}

type serverTrack struct {
	health, reach, psu, trust tracker
	psuMax                    int
	logs                      map[string]logMark
}

func newServerTrack() serverTrack {
	return serverTrack{health: tracker{confirmed: string(bmc.HealthOK)}, reach: tracker{confirmed: "up"},
		psu: tracker{confirmed: "ok"}, trust: tracker{confirmed: "ok"}, logs: map[string]logMark{}}
}

// Detector turns successive fleet states into events. It is owned by one goroutine
// (the service's watch loop) and only reads published, immutable server states.
type Detector struct {
	debounce time.Duration
	servers  map[string]serverTrack
	// acked reports acknowledged log entries (nil: none); they never raise a log event.
	acked func(serverID, log, entryID string, created time.Time) bool
}

// NewDetector returns a detector; debounce <= 0 takes DefaultDebounce.
func NewDetector(debounce time.Duration) *Detector {
	return &Detector{debounce: orDur(debounce, DefaultDebounce), servers: map[string]serverTrack{}}
}

// Observe compares states with what was seen before and returns the events to send.
func (d *Detector) Observe(states []fleet.ServerState, now time.Time) []Event {
	var out []Event
	seen := make(map[string]bool, len(states))
	for _, s := range states {
		seen[s.ID] = true
		tr, ok := d.servers[s.ID]
		if !ok {
			tr = newServerTrack()
		}
		var evs []Event
		tr, evs = d.observeServer(tr, s, now)
		d.servers[s.ID] = tr
		out = append(out, evs...)
	}
	d.forgetExcept(seen)
	return out
}

// Forget drops one server's state: its next observation starts from the healthy
// baseline (a problem still present is reported again after the debounce) and its logs
// are baselined again (entries seen meanwhile are not sent).
func (d *Detector) Forget(serverID string) { delete(d.servers, serverID) }

// forgetExcept drops the state of servers no longer in the fleet (removed, or disabled
// in Settings → Servers): they raise nothing, and a server that comes back starts from
// the healthy baseline instead of a stale "down" or "mismatch".
func (d *Detector) forgetExcept(seen map[string]bool) {
	for id := range d.servers {
		if !seen[id] {
			delete(d.servers, id)
		}
	}
}

func (d *Detector) observeServer(tr serverTrack, s fleet.ServerState, now time.Time) (serverTrack, []Event) {
	var out []Event
	var evs []Event
	tr.reach, evs = observeReach(tr.reach, s, now)
	out = append(out, evs...)
	tr.trust, evs = observeTrust(tr.trust, s, now)
	out = append(out, evs...)
	if !s.HasSnapshot || s.Stale {
		return tr, out
	}
	tr.health, evs = d.observeHealth(tr.health, s, now)
	out = append(out, evs...)
	tr, evs = d.observePSU(tr, s, now)
	out = append(out, evs...)
	tr, evs = observeLogs(tr, s, now, d.acked)
	return tr, append(out, evs...)
}

// verdict is the worst of the BMC rollup and every component health.
func verdict(snap bmc.Snapshot) bmc.Health {
	hs := []bmc.Health{snap.Health()}
	for _, t := range snap.Temperatures() {
		hs = append(hs, t.Health)
	}
	for _, f := range snap.Fans() {
		hs = append(hs, f.Health)
	}
	for _, p := range snap.PSUs() {
		hs = append(hs, p.Health)
	}
	return bmc.WorstHealth(hs...)
}

// Health signals of a host that is powered off (audit R2-01): its own non-OK state,
// below a critical sensor rollup. healthPlanned is a graceful shutdown this app ran for a
// user (fleet.PowerCause): information, not an alarm.
const (
	healthOff     = "Off"
	healthPlanned = "Off (planned)"
)

// healthValue is the health signal of a server: the worst sensor health, or Off while
// the host is powered off (or powering off) and nothing is critical.
func healthValue(s fleet.ServerState) string {
	snap := s.Snapshot
	v := verdict(snap)
	p := snap.PowerState()
	switch {
	case (p != bmc.PowerOff && p != bmc.PowerPoweringOff) || v == bmc.HealthCritical:
		return string(v)
	case s.PowerCause.Action == "graceful-shutdown" && s.PowerCause.By != "":
		return healthPlanned
	default:
		return healthOff
	}
}

// healthSeverity: critical for a critical rollup, and for a powered-off server that
// other systems depend on (tagged critical); information for a planned shutdown;
// warning otherwise.
func healthSeverity(h string, s fleet.ServerState) Severity {
	switch {
	case h == string(bmc.HealthCritical), h == healthOff && slices.Contains(s.Tags, "critical"):
		return SeverityCritical
	case h == healthPlanned:
		return SeverityInfo
	default:
		return SeverityWarning
	}
}

func (d *Detector) observeHealth(tr tracker, s fleet.ServerState, now time.Time) (tracker, []Event) {
	v := healthValue(s)
	if v == string(bmc.HealthUnknown) {
		return tr, nil
	}
	next, from, changed := tr.observe(v, now, d.debounce)
	if !changed {
		return next, nil
	}
	e := base(ClassHealth, s, "health/"+s.ID, now)
	switch {
	case v == string(bmc.HealthOK) && (from == healthOff || from == healthPlanned):
		e.Severity, e.Recovery = healthSeverity(from, s), true
		e.Title = s.Name + ": powered on again"
		e.Message = s.Name + "'s host is on again and reports OK health."
	case v == string(bmc.HealthOK):
		e.Severity, e.Recovery = healthSeverity(from, s), true
		e.Title = s.Name + ": health OK again"
		e.Message = fmt.Sprintf("%s reports OK health again (was %s).", s.Name, from)
	case v == healthPlanned:
		e.Severity = SeverityInfo
		e.Title = s.Name + ": powered off (graceful shutdown by " + s.PowerCause.By + ")"
		e.Message = fmt.Sprintf("%s's host is off after a graceful shutdown by %s through oob-manager (was %s).", s.Name, s.PowerCause.By, from)
	case v == healthOff:
		e.Severity = healthSeverity(v, s)
		e.Title = s.Name + ": powered off"
		e.Message = fmt.Sprintf("%s's host is powered off (was %s). Power it on from the server's Power menu if that is unexpected.", s.Name, from)
	default:
		e.Severity = healthSeverity(v, s)
		e.Title = fmt.Sprintf("%s: health %s", s.Name, v)
		e.Message = fmt.Sprintf("%s reports %s health (was %s). Open the server page for the failing sensors.", s.Name, v, from)
	}
	return next, []Event{e}
}

// unreachable: no good poll for longer than the stale threshold. A server that has not
// been polled yet is not judged.
func unreachable(s fleet.ServerState, now time.Time) (bool, bool) {
	if s.LastAttempt.IsZero() {
		return false, false
	}
	if !s.HasSnapshot {
		return !s.FailingSince.IsZero() && now.Sub(s.FailingSince) > s.StaleAfter, true
	}
	return s.Stale, true
}

func observeReach(tr tracker, s fleet.ServerState, now time.Time) (tracker, []Event) {
	down, known := unreachable(s, now)
	if !known || s.Restarting {
		// An expected BMC restart (tech_doc §37) is announced by the bmc class; the
		// silence it causes is not an outage until its deadline passes.
		return tr, nil
	}
	v := map[bool]string{true: "down", false: "up"}[down]
	next, _, changed := tr.observe(v, now, 0)
	if !changed {
		return next, nil
	}
	e := base(ClassReachability, s, "reach/"+s.ID, now)
	e.Severity = SeverityCritical
	if !down {
		e.Recovery = true
		e.Title = s.Name + ": BMC reachable again"
		e.Message = s.Name + "'s BMC answers again; readings are current."
		return next, []Event{e}
	}
	e.Title = s.Name + ": BMC unreachable"
	e.Message = fmt.Sprintf("No successful poll of %s's BMC for more than %s (last error: %s). Readings are stale.",
		s.Name, s.StaleAfter.Round(time.Second), orText(string(s.LastError), "none"))
	return next, []Event{e}
}

// observeTrust reports a TLS failure of the BMC connection: with a pinned certificate
// this is a fingerprint mismatch (a replaced certificate, or someone in the middle).
func observeTrust(tr tracker, s fleet.ServerState, now time.Time) (tracker, []Event) {
	var v string
	switch {
	case s.PinMismatch, s.LastError == bmc.ClassTLS: // S3 pauses polling on a pin mismatch
		v = "mismatch"
	case s.ConsecutiveFailures == 0 && s.HasSnapshot:
		v = "ok"
	default:
		return tr, nil
	}
	next, _, changed := tr.observe(v, now, 0)
	if !changed {
		return next, nil
	}
	e := TrustEvent(s.ID, s.Name, TrustTLS, v == "ok", now)
	return next, []Event{e}
}

// TrustEvent is a certificate or SSH host key mismatch (or its resolution). The poller
// reports TLS pin failures today; settings slice S3 calls this for its TOFU checks
// (what = "TLS certificate" or "SSH host key").
func TrustEvent(serverID, name, what string, resolved bool, now time.Time) Event {
	e := Event{ID: newEventID(), Class: ClassTrust, Severity: SeverityCritical, ServerID: serverID, ServerName: name,
		Key: "trust/" + serverID + "/" + what, At: now, Recovery: resolved}
	if resolved {
		e.Title = name + ": " + what + " check passes again"
		e.Message = "The " + what + " of " + name + "'s BMC matches the pinned value again."
		return e
	}
	e.Title = name + ": " + what + " mismatch"
	e.Message = "The " + what + " of " + name + "'s BMC does not match the pinned value. Polling of this server fails " +
		"until it is resolved. Check the BMC before accepting a new fingerprint."
	return e
}

func (d *Detector) observePSU(tr serverTrack, s fleet.ServerState, now time.Time) (serverTrack, []Event) {
	psus := s.Snapshot.PSUs()
	if len(psus) == 0 || s.Snapshot.PowerTelemetry() == bmc.PowerTelemetryUnavailable {
		return tr, nil
	}
	tr.psuMax = max(tr.psuMax, len(psus))
	if tr.psuMax < 2 {
		return tr, nil
	}
	healthy := 0
	for _, p := range psus {
		if p.Health == bmc.HealthOK {
			healthy++
		}
	}
	v := map[bool]string{true: "ok", false: "lost"}[healthy >= tr.psuMax]
	var changed bool
	tr.psu, _, changed = tr.psu.observe(v, now, d.debounce)
	if !changed {
		return tr, nil
	}
	e := base(ClassPSU, s, "psu/"+s.ID, now)
	e.Severity = SeverityCritical
	if v == "ok" {
		e.Recovery = true
		e.Title = s.Name + ": power supply redundancy restored"
		e.Message = fmt.Sprintf("All %d power supplies of %s are healthy again.", tr.psuMax, s.Name)
		return tr, []Event{e}
	}
	e.Title = s.Name + ": power supply redundancy lost"
	e.Message = fmt.Sprintf("Only %d of %d power supplies of %s are healthy. One more failure powers the server off.",
		healthy, tr.psuMax, s.Name)
	return tr, []Event{e}
}

func base(c Class, s fleet.ServerState, key string, now time.Time) Event {
	return Event{ID: newEventID(), Class: c, ServerID: s.ID, ServerName: s.Name, Key: key, At: now}
}

func orText(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

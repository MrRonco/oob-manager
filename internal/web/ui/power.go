package ui

import (
	"context"
	"net/http"
	"slices"
	"time"

	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
	"oob-manager/internal/power"
)

// formPower is the CSRF form name of the power confirm pages.
const formPower = "power"

// criticalTag is the config tag that marks a server other systems depend on.
const criticalTag = "critical"

// Power is the power service (*power.Service). Request may take as long as a BMC login
// plus the reset POST; the outcome of the transition arrives later through Last.
type Power interface {
	Info(id string) power.Info
	CooldownLeft(id string) time.Duration
	Last(id string) (power.Operation, bool)
	Request(ctx context.Context, id string, a power.Action, actor power.Actor) error
}

// powerRoutes: GET renders the confirm interstitial, POST runs the action. Without
// Deps.Power both answer 404 and the Power menu keeps every action disabled.
func (s *server) powerRoutes(mux *http.ServeMux) {
	mux.Handle("GET /servers/{id}/power/{action}", s.withSession(s.powerConfirmPage))
	mux.Handle("POST /servers/{id}/power/{action}", s.withSession(s.powerSubmit))
}

func powerPath(id string, a power.Action) string { return "/servers/" + id + "/power/" + string(a) }

// serverHome is a server's Overview tab, where the Now panel shows the outcome of a
// power action or a BMC restart (the Operations tab was retired in round-2 slice C).
func serverHome(id string) string { return "/servers/" + id }

// fanPath is a server's Fan boost page (More ▾ → Fan boost…).
func fanPath(id string) string { return "/servers/" + id + "/fan" }

// powerTarget resolves the server (config ID) and the action (closed enum) from the path.
func (s *server) powerTarget(w http.ResponseWriter, r *http.Request) (ServerView, power.Action, bool) {
	if s.d.Power == nil {
		s.errorPage(w, r, http.StatusNotFound, "There is no page at this address.")
		return ServerView{}, "", false
	}
	v, ok := s.lookup(w, r)
	if !ok {
		return ServerView{}, "", false
	}
	a, ok := power.ParseAction(r.PathValue("action"))
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "There is no such power action.")
		return ServerView{}, "", false
	}
	return v, a, true
}

// blocked is why an action cannot be used now: a visible reason, an HTTP status and the
// audit error class. The zero value means it can be used.
type blocked struct {
	why    string
	status int
	class  string
}

// powerBlocked checks, in order: BMC support, operator login, role, a BMC restart in
// progress, power state (withState) and the per-server cooldown.
func (s *server) powerBlocked(v ServerView, p authz.Principal, a power.Action, withState bool) blocked {
	info := s.d.Power.Info(v.ID)
	switch {
	case !v.HasCapabilities:
		return blocked{"Support not determined yet: the BMC has not been read.", http.StatusConflict, "unsupported"}
	case !slices.Contains(v.Capabilities.ResetTypes(), a.ResetType()):
		return blocked{"Not offered by this BMC.", http.StatusConflict, "unsupported"}
	case !info.Operator:
		return blocked{"Needs an operator BMC account (credentials.operator in the config).", http.StatusConflict, "no_operator"}
	case s.d.Authorize(p, a.Authz(), true) != nil:
		return blocked{"Needs the " + roleFor(a) + " role.", http.StatusForbidden, "forbidden"}
	case v.Restarting || s.bmcResetInFlight(v.ID):
		return blocked{"The BMC is restarting; power actions wait until it is back.", http.StatusConflict, "bmc_restarting"}
	}
	if st := s.knownPowerState(v); withState && !a.Applies(st) {
		return blocked{stateReason(st), http.StatusConflict, "state"}
	}
	if left := s.d.Power.CooldownLeft(v.ID); left > 0 {
		return blocked{"Another power action ran a moment ago. " + tryAgainIn(left), http.StatusTooManyRequests, "cooldown"}
	}
	return blocked{}
}

func roleFor(a power.Action) string {
	if a.Forced() {
		return "admin"
	}
	return "operator"
}

func stateReason(st bmc.PowerState) string {
	if st == bmc.PowerOn || st == bmc.PowerPoweringOn {
		return "The server is already on."
	}
	return "The server is off."
}

// knownPowerState is the newest power state the app has: the poller's snapshot, or the
// state read while verifying a power action that finished after that snapshot.
func (s *server) knownPowerState(v ServerView) bmc.PowerState {
	st := bmc.PowerUnknown
	if v.HasSnapshot {
		st = v.Snapshot.PowerState()
	}
	op, ok := s.d.Power.Last(v.ID)
	if ok && op.Final() && op.State != "" && op.State != bmc.PowerUnknown &&
		(!v.HasSnapshot || op.FinishedAt.After(v.Snapshot.TakenAt())) {
		return op.State
	}
	return st
}

// denyPower audits a refused power request with the server and the action.
func (s *server) denyPower(r *http.Request, sess session, id string, a power.Action, class string) {
	_ = s.record(r, auditDenied(sess, id, string(a.Authz()), a.ResetType(), class))
}

func (s *server) powerConfirmPage(w http.ResponseWriter, r *http.Request, sess session) {
	v, a, ok := s.powerTarget(w, r)
	if !ok {
		return
	}
	if b := s.powerBlocked(v, sess.id.Principal(), a, true); b.why != "" {
		s.refusePower(w, r, sess, v.ID, a, b)
		return
	}
	s.renderConfirm(w, r, sess, s.powerSpec(v, a), http.StatusOK)
}

// refusePower audits a refusal and shows it on an error page.
func (s *server) refusePower(w http.ResponseWriter, r *http.Request, sess session, id string, a power.Action, b blocked) {
	s.denyPower(r, sess, id, a, b.class)
	if b.status == http.StatusTooManyRequests {
		setRetryAfter(w, s.d.Power.CooldownLeft(id))
	}
	s.errorPage(w, r, b.status, a.Label()+": "+b.why)
}

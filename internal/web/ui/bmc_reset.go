package ui

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/authz"
	"oob-manager/internal/bmcreset"
	"oob-manager/internal/store"
)

// BMC restart (tech_doc §37): Power ▾ → Restart BMC… and the confirm page at
// /servers/{id}/bmc/reset. The route is independent of the tab, so a redesign that moves
// the panel keeps the page.

// formBMC is the CSRF form name of the BMC restart confirm page.
const formBMC = "bmc"

// BMCResets is the BMC restart service (*bmcreset.Service). Request takes as long as a
// BMC login plus the POST; the verification arrives later through State.
type BMCResets interface {
	Info(id string) bmcreset.Info
	State(id string) bmcreset.State
	Request(ctx context.Context, id string, actor bmcreset.Actor) error
}

func bmcResetPath(id string) string { return "/servers/" + id + "/bmc/reset" }

func (s *server) bmcResetRoutes(mux *http.ServeMux) {
	mux.Handle("GET /servers/{id}/bmc/reset", s.withSession(s.bmcConfirmPage))
	mux.Handle("POST /servers/{id}/bmc/reset", s.withSession(s.bmcSubmit))
}

// bmcBlocked is why the restart cannot be requested now, in the order the POST checks
// availability: BMC support, operator login, role, restart window, power interlock,
// a privilege refusal, then the cooldown. The zero value means it can be.
func (s *server) bmcBlocked(v ServerView, p authz.Principal, tf timeFmt) blocked {
	info, st := s.d.BMCReset.Info(v.ID), s.d.BMCReset.State(v.ID)
	switch {
	case !v.HasCapabilities:
		return blocked{"Not determined yet: the BMC has not been read.", http.StatusConflict, "not_offered"}
	case !v.Capabilities.Flags().ManagerReset:
		return blocked{"Not offered by this BMC.", http.StatusConflict, "not_offered"}
	case !info.Operator:
		return blocked{"Needs an operator BMC account.", http.StatusConflict, "no_operator"}
	case s.d.Authorize(p, authz.BMCReset, true) != nil:
		return blocked{"Needs the admin role.", http.StatusForbidden, "forbidden"}
	case st.Restarting || v.Restarting:
		return blocked{"BMC is restarting (back by " + tf.full(restartUntil(v, st)) + ").", http.StatusConflict, "restarting"}
	case s.powerPending(v.ID):
		return blocked{"A power action is still being verified.", http.StatusConflict, "power_pending"}
	case st.PrivilegeRefused:
		return blocked{"The operator account lacks the privilege (last attempt).", http.StatusConflict, "privilege"}
	case st.CooldownLeft > 0:
		return blocked{"Cooling down for " + coolMinutes(st.CooldownLeft) + ".", http.StatusTooManyRequests, "cooldown"}
	}
	return blocked{}
}

func restartUntil(v ServerView, st bmcreset.State) time.Time {
	if st.Restarting {
		return st.Window.Deadline
	}
	return v.Restart.Until
}

// coolMinutes rounds a cooldown up to whole minutes ("1 min", "10 min").
func coolMinutes(d time.Duration) string {
	return strconv.Itoa(int((d+time.Minute-1)/time.Minute)) + " min"
}

// bmcResetInFlight reports a BMC restart being requested right now (login, discovery,
// POST) for the power interlock in the Power menu.
func (s *server) bmcResetInFlight(id string) bool {
	return s.d.BMCReset != nil && s.d.BMCReset.State(id).InFlight
}

func (s *server) powerPending(id string) bool {
	if s.d.Power == nil {
		return false
	}
	op, ok := s.d.Power.Last(id)
	return ok && !op.Final()
}

// bmcPanel is the BMC restart control (Power menu) and the BMC facts (Overview's System panel).
type bmcPanel struct {
	Model, Firmware string
	LastReset       string // "" renders "Not reported"
	Href, Why       string // the button: a link, or disabled with the reason
	Hidden          bool   // a viewer sees no control
	Status          *powerStatus
}

func (s *server) bmcPanelFor(v ServerView, sess session) bmcPanel {
	tf := sess.tf()
	p := bmcPanel{}
	if v.HasCapabilities {
		f := v.Capabilities.Flags()
		p.Model, p.Firmware = f.BMCModel, f.BMCFirmware
	}
	pr := sess.id.Principal()
	p.Hidden = s.d.Authorize(pr, authz.PowerOn, true) != nil // a viewer: status, not controls (audit R2-11)
	if s.d.BMCReset == nil {
		p.Why = notSetUp
		return p
	}
	st := s.d.BMCReset.State(v.ID)
	p.LastReset = lastResetText(v, st, tf)
	p.Status = bmcStatusFor(v, st, tf)
	if p.Hidden {
		return p
	}
	if b := s.bmcBlocked(v, pr, tf); b.why != "" {
		p.Why = b.why
	} else {
		p.Href = bmcResetPath(v.ID)
	}
	return p
}

// lastResetText: the BMC's own LastResetTime (iDRAC9), else the app's last verified
// restart (iDRAC8 reports none), else "" (Not reported).
func lastResetText(v ServerView, st bmcreset.State, tf timeFmt) string {
	if v.HasCapabilities && !v.Capabilities.Flags().BMCLastReset.IsZero() {
		return tf.full(v.Capabilities.Flags().BMCLastReset) + " (reported by the BMC)"
	}
	if st.HasVerified {
		return tf.full(st.LastVerified.RequestedAt) + " by " + st.LastVerified.By + " (requested here)"
	}
	return ""
}

// bmcStatusFor is the latest restart's outcome on the panel (nil: none since start).
func bmcStatusFor(v ServerView, st bmcreset.State, tf timeFmt) *powerStatus {
	if st.Restarting {
		return &powerStatus{healthView{"Restarting", "info"}, "BMC restarting · " +
			restartText(RestartWindow{Since: st.Window.RequestedAt, Until: st.Window.Deadline, By: st.Window.By}, tf) + "."}
	}
	if !st.HasLast {
		return nil
	}
	l := st.Last
	who := " (requested by " + l.By + " at " + tf.full(l.RequestedAt) + ")"
	switch {
	case l.Result == store.BMCResetVerified && l.Detail == store.BMCResetUnchanged:
		return &powerStatus{healthView{"Unconfirmed", "warn"},
			"The BMC answered again but did not report a restart" + who + "."}
	case l.Result == store.BMCResetVerified && l.Detail == store.BMCResetUnconfirmed:
		return &powerStatus{healthView{"Unconfirmed", "warn"}, "The BMC answers again, but the restart request got no answer " +
			"and the BMC does not report when it last restarted, so the restart is not confirmed" + who + "."}
	case l.Result == store.BMCResetVerified:
		return &powerStatus{healthView{"Done", "ok"}, "BMC back after " + downFor(l.BackAt.Sub(sentOr(l))) + who + "."}
	case l.Result == store.BMCResetTimeout:
		return &powerStatus{healthView{"Failed", "crit"}, timeoutText(l, v, tf) + who + "."}
	case l.Result == store.BMCResetRefused && st.PrivilegeRefused:
		return &powerStatus{healthView{"Failed", "crit"}, "The operator account lacks the privilege for this action" + who +
			". On Dell iDRAC it needs Configure iDRAC."}
	case l.Result == store.BMCResetRefused:
		return &powerStatus{healthView{"Failed", "crit"}, "The BMC refused the restart: " + failText(l.Class, "") + who + "."}
	}
	return nil
}

func timeoutText(l bmcreset.Record, _ ServerView, tf timeFmt) string {
	switch l.Class {
	case "config_changed":
		return "The server's connection settings changed during the restart, so it was no longer watched"
	case "unobserved":
		return "oob-manager was not running when the BMC was due back, so the restart was not confirmed"
	case "tls":
		return "The BMC came back with a certificate that does not match its pin"
	default:
		return "The BMC did not come back by " + tf.full(l.Deadline) + "; open the BMC web UI"
	}
}

// sentOr is when the restart was sent (the downtime starts there), else requested.
func sentOr(l bmcreset.Record) time.Time {
	if !l.SentAt.IsZero() {
		return l.SentAt
	}
	return l.RequestedAt
}

// downFor renders a downtime: "2 min 10 s", "45 s".
func downFor(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return strconv.Itoa(int(d/time.Second)) + " s"
	}
	m, sec := int(d/time.Minute), int((d%time.Minute)/time.Second)
	if sec == 0 {
		return strconv.Itoa(m) + " min"
	}
	return strconv.Itoa(m) + " min " + strconv.Itoa(sec) + " s"
}

// describeBMC names the BMC restart confirm path for the step-up page.
func (s *server) describeBMC(next string) string {
	if !strings.HasSuffix(next, "/bmc/reset") {
		return ""
	}
	if name := s.serverNameIn(next, "/bmc/reset"); name != "" {
		return "Restart BMC · " + name
	}
	return ""
}

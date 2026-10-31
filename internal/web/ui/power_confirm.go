package ui

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"oob-manager/internal/audit"
	"oob-manager/internal/power"
)

var (
	badgeSafe   = healthView{Label: "Safe action", Class: "info"}
	badgeForced = healthView{Label: "Forced action", Class: "crit"}
)

func auditDenied(sess session, serverID, action, resetType, class string) audit.Entry {
	return audit.Entry{Principal: sess.id.User.Username, Role: string(sess.id.User.Role), ServerID: serverID,
		Action: action, Params: map[string]any{"reset_type": resetType}, Result: audit.ResultDenied, ErrorClass: class}
}

// powerSpec is the confirm interstitial of action a on server v (direction B C-11):
// what happens, the critical and self-host warnings, the configured "What goes down"
// list, the typed server name when needed, and the step-up naming the action.
func (s *server) powerSpec(v ServerView, a power.Action) confirmView {
	info := s.d.Power.Info(v.ID)
	critical := slices.Contains(v.Tags, criticalTag)
	cv := confirmView{Title: a.Label() + " " + v.Name + "?", Badge: powerBadge(a), Tier: powerTier(a), Heading: "What happens",
		Consequences: powerConsequences(v.Name, a),
		Facts: []kv{{"Server", v.Name}, {"Power now", powerLabel(s.knownPowerState(v))},
			{"Sent to the BMC", "ComputerSystem.Reset, ResetType " + a.ResetType()}},
		Button: a.Label() + " " + v.Name, CancelHref: serverHome(v.ID),
		ActionLabel: a.Label() + " · " + v.Name, form: formPower, serverID: v.ID,
		chrome: func(sess session, title string, body any) layoutData {
			return s.serverLayout(sess, v, title, "Power", body)
		}}
	if critical {
		cv.Warnings = append(cv.Warnings, v.Name+" is tagged critical: other systems depend on it.")
	}
	if a.TakesDown() {
		cv.Impact = info.Impact
		if info.SelfHost {
			cv.Warnings = append(cv.Warnings, "This server runs oob-manager; the console will go offline until it boots.")
			if !a.Restarts() {
				cv.Warnings = append(cv.Warnings, "Powering it on again needs another way in, such as the BMC's own web interface.")
			}
		}
	}
	cv.Typed, cv.TypedWhy = typedFor(v.Name, a, critical, info.SelfHost)
	return cv
}

func powerBadge(a power.Action) healthView {
	if a.Forced() {
		return badgeForced
	}
	return badgeSafe
}

// powerTier (audit R2-15): forced actions are danger; a graceful stop or restart has
// service impact but recovers (caution); powering on is neutral.
func powerTier(a power.Action) string {
	switch {
	case a.Forced():
		return tierDanger
	case a.TakesDown():
		return tierCaution
	default:
		return ""
	}
}

func powerConsequences(name string, a power.Action) []string {
	out := []string{a.Effect()}
	switch {
	case a == power.On:
		out = append(out, "Its services start as it boots.")
	case a.Restarts():
		out = append(out, "Everything running on "+name+" stops.", name+" starts again by itself; its services return once it has booted.")
	default:
		out = append(out, "Everything running on "+name+" stops.", name+" stays off until someone powers it on.")
	}
	return append(out, "oob-manager then watches the power state and shows the result on the server's Overview tab.",
		"Further power actions on this server wait "+humanDuration(power.DefaultCooldown)+".")
}

// typedFor: forced actions always need the typed name; safe actions that take down a
// critical server or the server oob-manager runs on need it too. Power on never does.
func typedFor(name string, a power.Action, critical, selfHost bool) (typed, why string) {
	switch {
	case a.Forced():
		return name, "Forced actions skip the operating system."
	case a.TakesDown() && selfHost:
		return name, "This server runs oob-manager."
	case a.TakesDown() && critical:
		return name, name + " is a critical server."
	}
	return "", ""
}

// powerSubmit runs a confirmed power action. Order: session (withSession), server and
// action from the path, CSRF, availability (support, operator login, role, cooldown),
// the confirm field, the typed name, the step-up (inline code), authorization with the
// fresh step-up, the per-user action limit, then the power service. Every refusal is
// audited; the service audits the attempt itself.
func (s *server) powerSubmit(w http.ResponseWriter, r *http.Request, sess session) {
	v, a, ok := s.powerTarget(w, r)
	if !ok {
		return
	}
	form, ok := parseForm(w, r)
	if !ok || !s.csrf.verify(form.Get(csrfField), formPower, sessionBinding(sess.token)) {
		s.denyPower(r, sess, v.ID, a, "csrf")
		s.errorPage(w, r, http.StatusForbidden, msgFormExpired)
		return
	}
	if b := s.powerBlocked(v, sess.id.Principal(), a, false); b.why != "" {
		s.refusePower(w, r, sess, v.ID, a, b)
		return
	}
	spec := s.powerSpec(v, a)
	switch {
	case form.Get("confirm") != confirmYes:
		s.denyPower(r, sess, v.ID, a, "unconfirmed")
		redirectLocal(w, r, powerPath(v.ID, a))
		return
	case spec.Typed != "" && form.Get("typed") != spec.Typed:
		s.denyPower(r, sess, v.ID, a, "confirm_mismatch")
		spec.Error, spec.TypedInvalid = "The name you typed does not match. Type it exactly, including case.", true
		s.renderConfirm(w, r, sess, spec, http.StatusUnprocessableEntity)
		return
	}
	if sess, ok = s.confirmStepUp(w, r, sess, a.Authz(), form.Get("code"), spec); !ok {
		return
	}
	if !s.authorizePower(w, r, sess, v.ID, a) {
		return
	}
	s.runPower(w, r, sess, v, a, spec)
}

// authorizePower re-checks role and step-up after the inline code, then the per-user
// action limit (security.md §3: 10/min per user).
func (s *server) authorizePower(w http.ResponseWriter, r *http.Request, sess session, id string, a power.Action) bool {
	if err := s.d.Authorize(sess.id.Principal(), a.Authz(), s.d.Auth.StepUpFresh(sess.id.Session)); err != nil {
		s.denyPower(r, sess, id, a, authzClass(err))
		s.errorPage(w, r, http.StatusForbidden, a.Label()+": you are not allowed to do this.")
		return false
	}
	if ok, wait := s.changeLimit.allow("power:" + sess.id.User.ID); !ok {
		s.denyPower(r, sess, id, a, "rate_limited")
		setRetryAfter(w, wait)
		s.errorPage(w, r, http.StatusTooManyRequests, "Too many power requests in a short time. "+tryAgainIn(wait))
		return false
	}
	return true
}

// runPower calls the service without the request's deadline, so a slow BMC login
// cannot cut a reset in half. When the page's own deadline passes first, the browser
// is sent to the server's Overview tab, where the operation shows as "Sending".
func (s *server) runPower(w http.ResponseWriter, r *http.Request, sess session, v ServerView, a power.Action, spec confirmView) {
	actor := power.Actor{Username: sess.id.User.Username, Role: string(sess.id.User.Role), SrcIP: clientIP(r), AuthMethod: "local"}
	done := make(chan error, 1)
	go func() { done <- s.d.Power.Request(context.WithoutCancel(r.Context()), v.ID, a, actor) }()
	var err error
	select {
	case err = <-done:
	case <-r.Context().Done():
	}
	if err == nil {
		redirectLocal(w, r, serverHome(v.ID)+"#now-h")
		return
	}
	status, msg := powerError(err)
	if errors.Is(err, power.ErrCoolingDown) {
		setRetryAfter(w, s.d.Power.CooldownLeft(v.ID))
	}
	spec.Error = msg
	s.renderConfirm(w, r, sess, spec, status)
}

// powerError maps a service error to a status and a sentence (BMC text is never shown).
func powerError(err error) (int, string) {
	var cd *power.CooldownError
	switch {
	case errors.As(err, &cd):
		return http.StatusTooManyRequests, "Another power action ran a moment ago. " + tryAgainIn(cd.Left)
	case errors.Is(err, power.ErrUnsupported):
		return http.StatusConflict, "The BMC does not offer this action."
	case errors.Is(err, power.ErrState):
		return http.StatusConflict, "The server's power state changed: this action no longer applies. Check the server's Overview tab."
	case errors.Is(err, power.ErrNoOperator), errors.Is(err, power.ErrNotConfigured):
		return http.StatusConflict, "Power control is not set up for this server."
	case errors.Is(err, power.ErrBMCRestarting):
		return http.StatusConflict, "The BMC is restarting; power actions wait until it is back."
	case errors.Is(err, power.ErrAudit):
		return http.StatusServiceUnavailable, "The audit log could not be written, so nothing was sent. Try again later."
	default:
		return http.StatusBadGateway, "The BMC did not confirm the request. Check the server's Overview tab and the server before trying again."
	}
}

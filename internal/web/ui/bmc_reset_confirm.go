package ui

import (
	"context"
	"errors"
	"net/http"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmcreset"
	"oob-manager/internal/config"
)

var badgeBMCReset = healthView{Label: "Monitoring pauses", Class: "crit"}

// bmcTarget resolves the server from the path (404 without the service or the server).
func (s *server) bmcTarget(w http.ResponseWriter, r *http.Request) (ServerView, bool) {
	if s.d.BMCReset == nil {
		s.errorPage(w, r, http.StatusNotFound, "There is no page at this address.")
		return ServerView{}, false
	}
	return s.lookup(w, r)
}

func (s *server) denyBMC(r *http.Request, sess session, id, class string) {
	_ = s.record(r, audit.Entry{Principal: sess.id.User.Username, Role: string(sess.id.User.Role), ServerID: id,
		Action: string(authz.BMCReset), Params: map[string]any{"reset_type": bmcreset.ResetType},
		Result: audit.ResultDenied, ErrorClass: class})
}

// refuseBMC audits a refusal and shows it on an error page.
func (s *server) refuseBMC(w http.ResponseWriter, r *http.Request, sess session, id string, b blocked) {
	s.denyBMC(r, sess, id, b.class)
	if b.status == http.StatusTooManyRequests {
		setRetryAfter(w, s.d.BMCReset.State(id).CooldownLeft)
	}
	s.errorPage(w, r, b.status, "Restart BMC: "+b.why)
}

func (s *server) bmcConfirmPage(w http.ResponseWriter, r *http.Request, sess session) {
	v, ok := s.bmcTarget(w, r)
	if !ok {
		return
	}
	if b := s.bmcBlocked(v, sess.id.Principal(), sess.tf()); b.why != "" {
		s.refuseBMC(w, r, sess, v.ID, b)
		return
	}
	s.renderConfirm(w, r, sess, s.bmcSpec(v), http.StatusOK)
}

// bmcSpec is the confirm interstitial (C-11): what the restart costs, the open
// consoles it ends, the fan and self-host notes, the typed name (always) and the
// step-up naming the action. Cancel is the default focus.
func (s *server) bmcSpec(v ServerView) confirmView {
	info := s.d.BMCReset.Info(v.ID)
	f := v.Capabilities.Flags()
	cv := confirmView{Title: "Restart the BMC of " + v.Name + "?", Badge: badgeBMCReset, Tier: tierDanger,
		Heading: "What happens", Consequences: bmcConsequences(info),
		Facts: []kv{{"Server", v.Name}, {"BMC", joinNonEmpty(f.BMCModel, f.BMCFirmware)},
			{"Sent to the BMC", "Manager.Reset, ResetType " + bmcreset.ResetType},
			{"Expected back within", humanDuration(info.Deadline)}},
		Button: "Restart BMC of " + v.Name, CancelHref: serverHome(v.ID) + "#now-h",
		ActionLabel: "Restart BMC · " + v.Name, form: formBMC, serverID: v.ID,
		Typed: v.Name, TypedWhy: "Monitoring pauses and every console on this server closes.",
		chrome: func(sess session, title string, body any) layoutData {
			return s.serverLayout(sess, v, title, "BMC restart", body)
		}}
	cv.Warnings = s.bmcWarnings(v, info)
	return cv
}

func bmcConsequences(info bmcreset.Info) []string {
	return []string{
		"Every console on this server closes now: graphical, serial, and a native console opened from the BMC.",
		"Sensors, logs and power control are unavailable for about 2–5 minutes (oob-manager waits up to " +
			humanDuration(info.Deadline) + ").",
		"Fans may run at full speed until the BMC is back. Dell servers commonly do this while the iDRAC reboots; it is not a fault.",
		"The host keeps running: its operating system and services are not affected.",
		"oob-manager then shows the result on the server's Overview tab, and further BMC restarts of this server wait " +
			humanDuration(bmcreset.DefaultCooldown) + ".",
	}
}

// bmcWarnings names the consoles that end, the self-host case and the fan setup.
func (s *server) bmcWarnings(v ServerView, info bmcreset.Info) []string {
	var out []string
	if s.d.Consoles != nil {
		if st := s.d.Consoles.Status(v.ID); st.InUse {
			out = append(out, "The graphical console of "+st.Active.Username+" is open; it ends now.")
		}
	}
	if s.d.Serial != nil {
		if st := s.d.Serial.Status(v.ID); st.InUse {
			out = append(out, "The serial console of "+st.Active.Username+" is open; it ends now.")
		}
	}
	if info.SelfHost {
		out = append(out, "This server runs oob-manager. The app is not affected: only the BMC restarts, not the host.")
	}
	if s.d.Fans != nil {
		if p, ok := s.d.Fans.Policy(v.ID); ok {
			switch p.Mode {
			case config.FanHostLease:
				out = append(out, "A host fan script that reads the BMC in-band (IPMI over KCS) cannot read sensors during the restart; it must fail safe. The lease file is not touched.")
			case config.FanRedfishFloor:
				out = append(out, "An active fan floor is applied again once the BMC is back.")
			}
		}
	}
	return out
}

func joinNonEmpty(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + " · " + b
	}
}

// bmcSubmit runs a confirmed BMC restart. Order (security.md §3c, as for forced power
// actions): session (withSession), server from the path, CSRF, availability, the confirm
// field, the typed name (always), the step-up (inline code), authorization with the
// fresh step-up, the per-user action limit, then the service. Every refusal is audited;
// the service audits the attempt itself.
func (s *server) bmcSubmit(w http.ResponseWriter, r *http.Request, sess session) {
	v, ok := s.bmcTarget(w, r)
	if !ok {
		return
	}
	form, ok := parseForm(w, r)
	if !ok || !s.csrf.verify(form.Get(csrfField), formBMC, sessionBinding(sess.token)) {
		s.denyBMC(r, sess, v.ID, "csrf")
		s.errorPage(w, r, http.StatusForbidden, msgFormExpired)
		return
	}
	if b := s.bmcBlocked(v, sess.id.Principal(), sess.tf()); b.why != "" {
		s.refuseBMC(w, r, sess, v.ID, b)
		return
	}
	spec := s.bmcSpec(v)
	switch {
	case form.Get("confirm") != confirmYes:
		s.denyBMC(r, sess, v.ID, "unconfirmed")
		redirectLocal(w, r, bmcResetPath(v.ID))
		return
	case form.Get("typed") != spec.Typed:
		s.denyBMC(r, sess, v.ID, "confirm_mismatch")
		spec.Error, spec.TypedInvalid = "The name you typed does not match. Type it exactly, including case.", true
		s.renderConfirm(w, r, sess, spec, http.StatusUnprocessableEntity)
		return
	}
	if sess, ok = s.confirmStepUp(w, r, sess, authz.BMCReset, form.Get("code"), spec); !ok {
		return
	}
	if !s.authorizeBMC(w, r, sess, v.ID) {
		return
	}
	s.runBMCReset(w, r, sess, v, spec)
}

// authorizeBMC re-checks role and step-up after the inline code, then the per-user
// action limit (10/min, key bmc:<user>).
func (s *server) authorizeBMC(w http.ResponseWriter, r *http.Request, sess session, id string) bool {
	if err := s.d.Authorize(sess.id.Principal(), authz.BMCReset, s.d.Auth.StepUpFresh(sess.id.Session)); err != nil {
		s.denyBMC(r, sess, id, authzClass(err))
		s.errorPage(w, r, http.StatusForbidden, "Restart BMC: you are not allowed to do this.")
		return false
	}
	if ok, wait := s.changeLimit.allow("bmc:" + sess.id.User.ID); !ok {
		s.denyBMC(r, sess, id, "rate_limited")
		setRetryAfter(w, wait)
		s.errorPage(w, r, http.StatusTooManyRequests, "Too many BMC restart requests in a short time. "+tryAgainIn(wait))
		return false
	}
	return true
}

// runBMCReset calls the service without the request's deadline, so a slow BMC login
// cannot cut the reset in half; if the page's deadline passes first, the browser goes to
// the server's Overview tab, which shows the restart window.
func (s *server) runBMCReset(w http.ResponseWriter, r *http.Request, sess session, v ServerView, spec confirmView) {
	actor := bmcreset.Actor{Username: sess.id.User.Username, Role: string(sess.id.User.Role), SrcIP: clientIP(r), AuthMethod: "local"}
	done := make(chan error, 1)
	go func() { done <- s.d.BMCReset.Request(context.WithoutCancel(r.Context()), v.ID, actor) }()
	var err error
	select {
	case err = <-done:
	case <-r.Context().Done():
	}
	if err == nil {
		redirectLocal(w, r, serverHome(v.ID)+"#now-h")
		return
	}
	status, msg := bmcError(err)
	var cd *bmcreset.CooldownError
	if errors.As(err, &cd) {
		setRetryAfter(w, cd.Left)
	}
	spec.Error = msg
	s.renderConfirm(w, r, sess, spec, status)
}

// bmcError maps a service error to a status and a sentence (BMC text is never shown).
func bmcError(err error) (int, string) {
	var cd *bmcreset.CooldownError
	switch {
	case errors.As(err, &cd):
		return http.StatusTooManyRequests, "This BMC was restarted a moment ago. " + tryAgainIn(cd.Left)
	case errors.Is(err, bmcreset.ErrRestarting):
		return http.StatusConflict, "The BMC is already restarting."
	case errors.Is(err, bmcreset.ErrPowerPending):
		return http.StatusConflict, "A power action is still being verified. Try again when it has finished."
	case errors.Is(err, bmcreset.ErrUnsupported):
		return http.StatusConflict, "The BMC does not offer this action."
	case errors.Is(err, bmcreset.ErrNoOperator), errors.Is(err, bmcreset.ErrNotConfigured):
		return http.StatusConflict, "BMC restart is not set up for this server."
	case errors.Is(err, bmcreset.ErrAudit):
		return http.StatusServiceUnavailable, "The audit log could not be written, so nothing was sent. Try again later."
	case errors.Is(err, bmcreset.ErrPrivilege):
		return http.StatusBadGateway, "The operator account lacks the privilege for this action (on Dell iDRAC: Configure iDRAC). Nothing was restarted."
	default:
		return http.StatusBadGateway, "The BMC did not accept the restart. Check the server's Overview tab before trying again."
	}
}

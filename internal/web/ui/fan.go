package ui

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"oob-manager/internal/authz"
	"oob-manager/internal/config"
	"oob-manager/internal/fan"
)

// fanActionTimeout bounds a lease start or end (redfish-floor logs in to the BMC, reads,
// PATCHes and logs out; iDRACs are slow).
const fanActionTimeout = 45 * time.Second

// leaseFields are the editable fields of the fan lease confirm page (the shared confirm
// interstitial, C-11/C-12): the floor, the duration choices and the safe minimum.
type leaseFields struct {
	Pct        string
	Durations  []durationOpt
	SafeMin    int
	PctInvalid bool
}

// badgeUndoable is the fan lease confirm badge: a lease ends by itself or with End now.
var badgeUndoable = reversible

// fanRoutes: start (two steps: review, then confirm) and End now.
func (s *server) fanRoutes(mux *http.ServeMux) {
	mux.Handle("POST /servers/{id}/fan/lease", s.withSession(s.fanStart))
	mux.Handle("POST /servers/{id}/fan/lease/end", s.withSession(s.fanEnd))
}

// fanTarget resolves the server and its fan policy; anything without fan control is 404.
func (s *server) fanTarget(w http.ResponseWriter, r *http.Request) (ServerView, fan.Policy, bool) {
	v, ok := s.lookup(w, r)
	if !ok {
		return ServerView{}, fan.Policy{}, false
	}
	if s.d.Fans != nil {
		if p, ok := s.d.Fans.Policy(v.ID); ok {
			return v, p, true
		}
	}
	s.errorPage(w, r, http.StatusNotFound, "Fan control is not configured for this server.")
	return ServerView{}, fan.Policy{}, false
}

// fanForm parses the form and checks its CSRF token and the role (without step-up).
func (s *server) fanForm(w http.ResponseWriter, r *http.Request, sess session, action authz.Action) (url.Values, bool) {
	form, ok := parseForm(w, r)
	if !ok || !s.csrf.verify(form.Get(csrfField), formFan, sessionBinding(sess.token)) {
		s.deny(r, sess, action, "csrf")
		s.errorPage(w, r, http.StatusForbidden, msgFormExpired)
		return nil, false
	}
	if s.d.Authorize(sess.id.Principal(), action, true) != nil {
		s.deny(r, sess, action, "forbidden")
		s.errorPage(w, r, http.StatusForbidden, "Fan leases need the operator role.")
		return nil, false
	}
	return form, true
}

func (s *server) fanStart(w http.ResponseWriter, r *http.Request, sess session) {
	v, p, ok := s.fanTarget(w, r)
	if !ok {
		return
	}
	form, ok := s.fanForm(w, r, sess, authz.FanLeaseCreate)
	if !ok {
		return
	}
	cv := s.fanSpec(v, p, form)
	req, err := fan.ParseRequest(form.Get("pct"), form.Get("minutes"), p)
	if err != nil {
		if form.Get("confirm") == confirmYes {
			s.deny(r, sess, authz.FanLeaseCreate, "invalid")
		}
		cv.Error, cv.Lease.PctInvalid = fanInputError(p), true
		s.renderConfirm(w, r, sess, cv, http.StatusUnprocessableEntity)
		return
	}
	cv.Consequences = fanConsequences(p, req, s.d.Now(), sess.tf())
	if form.Get("confirm") != confirmYes {
		s.renderConfirm(w, r, sess, cv, http.StatusOK)
		return
	}
	if sess, ok = s.confirmStepUp(w, r, sess, authz.FanLeaseCreate, form.Get("code"), cv); !ok {
		return
	}
	if !s.fanRate(w, r, sess, authz.FanLeaseCreate) {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), fanActionTimeout)
	defer cancel()
	if _, err := s.d.Fans.Start(ctx, fanActor(r, sess), v.ID, req); err != nil {
		status, msg := s.fanError(err)
		s.errorPage(w, r, status, msg)
		return
	}
	redirectLocal(w, r, fanPath(v.ID)+"?fan=started")
}

// fanEnd is End now: operator, CSRF, no step-up (PRD FR-14), rate limited.
func (s *server) fanEnd(w http.ResponseWriter, r *http.Request, sess session) {
	v, _, ok := s.fanTarget(w, r)
	if !ok {
		return
	}
	if _, ok := s.fanForm(w, r, sess, authz.FanLeaseEnd); !ok || !s.fanRate(w, r, sess, authz.FanLeaseEnd) {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), fanActionTimeout)
	defer cancel()
	err := s.d.Fans.End(ctx, fanActor(r, sess), v.ID)
	switch {
	case errors.Is(err, fan.ErrNoLease):
		redirectLocal(w, r, fanPath(v.ID)+"?fan=none")
	case err != nil:
		status, msg := s.fanError(err)
		s.errorPage(w, r, status, msg)
	default:
		redirectLocal(w, r, fanPath(v.ID)+"?fan=ended")
	}
}

func (s *server) fanRate(w http.ResponseWriter, r *http.Request, sess session, action authz.Action) bool {
	if ok, wait := s.fanLimit.allow("fan:" + sess.id.User.ID); !ok {
		s.deny(r, sess, action, "rate_limited")
		setRetryAfter(w, wait)
		s.errorPage(w, r, http.StatusTooManyRequests, "Too many fan changes in a short time. "+tryAgainIn(wait))
		return false
	}
	return true
}

func (s *server) fanError(err error) (int, string) {
	switch {
	case errors.Is(err, fan.ErrActive):
		return http.StatusConflict, "A lease is already active on this server. End it first, then start a new one."
	case errors.Is(err, fan.ErrApply):
		return http.StatusBadGateway, "The lease could not be applied, so nothing changed. Check that the BMC is reachable (or the lease directory is writable) and try again."
	case errors.Is(err, fan.ErrRelease):
		return http.StatusBadGateway, "The lease could not be ended yet. It still ends at its expiry time; try End now again in a moment."
	case errors.Is(err, fan.ErrNotConfigured):
		return http.StatusNotFound, "Fan control is not configured for this server."
	case errors.Is(err, fan.ErrAudit):
		return http.StatusServiceUnavailable, "The audit log could not be written, so nothing changed. Try again later."
	default:
		s.d.Logger.Error("fan lease change failed", "err", err)
		return http.StatusInternalServerError, "The fan lease could not be changed. Try again."
	}
}

func fanActor(r *http.Request, sess session) fan.Actor {
	return fan.Actor{Username: sess.id.User.Username, Role: string(sess.id.User.Role), IP: clientIP(r), Method: "local"}
}

func fanInputError(p fan.Policy) string {
	return "Enter a floor from " + strconv.Itoa(p.SafeMin) + " to 100 % (whole number) and pick a duration."
}

// fanSpec is the shared confirm interstitial for starting a lease on v: the fields keep
// what was typed (the floor capped at three characters), the duration falls back to the
// policy's choices.
func (s *server) fanSpec(v ServerView, p fan.Policy, form url.Values) confirmView {
	minutes, _ := strconv.Atoi(form.Get("minutes"))
	pct := form.Get("pct")
	if len(pct) > 3 {
		pct = pct[:3]
	}
	return confirmView{Title: "Start a fan lease on " + v.Name + "?", Badge: badgeUndoable, Heading: "What happens",
		EmptyNote: "Fix the values to see what the lease will do.",
		Lease:     &leaseFields{Pct: pct, Durations: durationOpts(p, minutes), SafeMin: p.SafeMin},
		Button:    "Start lease", CancelHref: fanPath(v.ID), ActionLabel: "Start fan lease · " + v.Name,
		form: formFan, serverID: v.ID,
		chrome: func(sess session, title string, body any) layoutData {
			return s.serverLayout(sess, v, title, "Fan lease", body)
		}}
}

func fanConsequences(p fan.Policy, req fan.Request, now time.Time, tf timeFmt) []string {
	until := tf.full(now.Add(req.Duration))
	out := []string{"Fans run at least at " + strconv.Itoa(req.Pct) + " % until " + until + " (" +
		humanDuration(req.Duration) + ")."}
	switch p.Mode {
	case config.FanHostLease:
		out = append(out, "The host fan script applies it on its next run (within about a minute). When its own curve wants more, the curve wins.",
			"The host stops honoring the lease at the end time even if this app is down.")
	case config.FanRedfishFloor:
		out = append(out, "The BMC's minimum fan speed is raised; it stays in automatic control and can still go faster.",
			"The previous minimum is restored when the lease ends (the BMC may clamp the floor to its own range).")
	}
	return append(out, "You can end it earlier with End now.")
}

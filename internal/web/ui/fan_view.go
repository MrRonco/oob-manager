package ui

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"oob-manager/internal/authz"
	"oob-manager/internal/config"
	"oob-manager/internal/fan"
	"oob-manager/internal/store"
)

// Fans is the fan lease service (*fan.Service). Status never contacts a BMC; Start and
// End may (redfish-floor), so the UI calls them with their own deadline.
type Fans interface {
	Policy(serverID string) (fan.Policy, bool)
	Status(ctx context.Context, serverID string) (fan.Status, error)
	Start(ctx context.Context, a fan.Actor, serverID string, r fan.Request) (store.FanLease, error)
	End(ctx context.Context, a fan.Actor, serverID string) error
}

// formFan is the CSRF form name of the lease start and End now forms.
const formFan = "fan"

// fanLeaseView is the active lease on the card.
type fanLeaseView struct {
	By, Until, UntilISO, Left string
	Pct                       int
	Pending                   bool
}

// durationOpt is one choice of the duration select.
type durationOpt struct {
	Minutes  int
	Label    string
	Selected bool
}

// fanCard is the Fan lease panel of the Fan boost page (PRD FR-14): who owns the fans,
// what the enforcing side reported, the lease countdown, End now, and the start form.
type fanCard struct {
	ID          string
	Unavailable string // set: fan control is off for this server (the reason)
	Mode        string
	Badge       healthView
	Owner       string
	Applied     string
	Reported    string
	Lease       *fanLeaseView
	Warning     string
	Notice      string
	CanStart    bool
	CanEnd      bool
	Why         string // why the viewer cannot start or end a lease
	CSRF        string
	SafeMin     int
	Pct         string
	Durations   []durationOpt
	StepUp      stepUpNote
}

func modeLabel(m config.FanMode) string {
	switch m {
	case config.FanHostLease:
		return "Host fan script with a lease file. The host's own curve stays in charge and a lease can only raise it."
	case config.FanRedfishFloor:
		return "BMC minimum fan speed. The BMC stays in automatic control; a lease raises its lower bound."
	default:
		return ""
	}
}

// fanCardFor builds the card. A failure to read the state is shown on the card, never
// as a page error: the rest of the page stays usable.
func (s *server) fanCardFor(r *http.Request, sess session, v ServerView) fanCard {
	c := fanCard{ID: v.ID, Notice: fanNotice(r.URL.Query().Get("fan"))}
	if s.d.Fans == nil {
		c.Unavailable = "Fan control is not set up in this installation. Fans follow the BMC or the host's own script."
		return c
	}
	p, ok := s.d.Fans.Policy(v.ID)
	if !ok {
		c.Unavailable = "Fan control is off for this server (fan mode none). Fans follow the BMC or the host's own script."
		return c
	}
	c.Mode, c.SafeMin, c.Durations = modeLabel(p.Mode), p.SafeMin, durationOpts(p, 30)
	c.Pct = strconv.Itoa(max(p.SafeMin, 50))
	st, err := s.d.Fans.Status(r.Context(), v.ID)
	if err != nil {
		s.d.Logger.Error("fan status", "server", v.ID, "err", err)
		c.Warning, c.Badge = "The fan lease state could not be read.", healthView{Label: "Unknown", Class: "unknown"}
		return c
	}
	s.describeFanStatus(&c, p, st, sess.tf())
	principal := sess.id.Principal()
	c.CanStart = !st.HasLease && s.d.Authorize(principal, authz.FanLeaseCreate, true) == nil
	c.CanEnd = st.HasLease && s.d.Authorize(principal, authz.FanLeaseEnd, true) == nil
	if s.d.Authorize(principal, authz.FanLeaseCreate, true) != nil {
		c.Why = "Fan leases need the operator role."
	}
	c.CSRF = s.csrf.issue(formFan, sessionBinding(sess.token))
	c.StepUp = s.stepUpNoteFor(r, sess)
	return c
}

func (s *server) describeFanStatus(c *fanCard, p fan.Policy, st fan.Status, tf timeFmt) {
	c.Warning = st.Warning
	if st.HasPct {
		c.Applied = strconv.Itoa(st.AppliedPct) + " %"
	}
	if !st.ReportedAt.IsZero() {
		c.Reported = tf.full(st.ReportedAt)
	}
	switch {
	case st.HasLease:
		l := st.Lease
		pending := !st.Applied
		c.Lease = &fanLeaseView{By: l.RequestedBy, Pct: l.Pct, Until: tf.full(l.ExpiresAt),
			UntilISO: l.ExpiresAt.UTC().Format(time.RFC3339), Left: leftText(st.Remaining), Pending: pending}
		c.Owner = "Lease by " + l.RequestedBy + ": at least " + strconv.Itoa(l.Pct) + " %"
		c.Badge = healthView{Label: "Applied", Class: "ok"}
		if pending {
			c.Badge = healthView{Label: "Pending", Class: "info"}
		}
	case p.Mode == config.FanRedfishFloor:
		c.Owner, c.Badge = "BMC automatic (no minimum set by this app)", healthView{Label: "No lease", Class: "info"}
	default:
		c.Owner, c.Badge = "Host fan curve", healthView{Label: "No lease", Class: "info"}
	}
	switch st.Owner {
	case fan.OwnerGuard:
		c.Owner, c.Badge = "Thermal guard: BMC automatic", healthView{Label: "Guard", Class: "warn"}
	case fan.OwnerCurve:
		if st.HasLease && st.Applied {
			c.Owner = "Host fan curve (above the lease floor of " + strconv.Itoa(st.Lease.Pct) + " %)"
		}
	}
	if c.Warning != "" && c.Badge.Class != "warn" {
		c.Badge = healthView{Label: c.Badge.Label + ", check", Class: "warn"}
	}
}

func leftText(d time.Duration) string {
	m := int((d + time.Minute - 1) / time.Minute)
	if m <= 0 {
		return "ending now"
	}
	return humanDuration(time.Duration(m)*time.Minute) + " left"
}

func durationOpts(p fan.Policy, selected int) []durationOpt {
	choices := p.DurationChoices()
	out := make([]durationOpt, 0, len(choices))
	found := false
	for _, m := range choices {
		found = found || m == selected
	}
	for i, m := range choices {
		sel := m == selected || (!found && i == 0)
		out = append(out, durationOpt{Minutes: m, Label: humanDuration(time.Duration(m) * time.Minute), Selected: sel})
	}
	return out
}

// fanNotice maps the closed ?fan= values of the post-redirect page to a sentence.
func fanNotice(v string) string {
	switch v {
	case "started":
		return "Lease started."
	case "ended":
		return "Lease ended. The normal fan control is back in charge."
	case "none":
		return "There was no active lease to end."
	default:
		return ""
	}
}

package bmcsec

import (
	"context"
	"maps"
	"strconv"
	"strings"

	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
	"oob-manager/internal/notify"
	"oob-manager/internal/store"
)

// Notification bookkeeping items (security_notified.item).
const (
	itemFinding = "f:"
	itemCert    = "cert:"
)

func (s *Service) loadNotified(ctx context.Context) error {
	if s.cfg.DB == nil {
		return nil
	}
	rows, err := s.cfg.DB.Security().Notified(ctx)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if s.notified[r.ServerID] == nil {
			s.notified[r.ServerID] = map[string]string{}
		}
		s.notified[r.ServerID][r.Item] = r.Value
	}
	return nil
}

// watch compares each polled server's open findings with what was already notified and
// sends one message per server for the new ones, plus certificate reminders. The state
// of servers that are no longer polled is dropped (a server enabled again starts over).
func (s *Service) watch(ctx context.Context) {
	present := map[string]bool{}
	for _, st := range s.cfg.Fleet.Servers() {
		present[st.ID] = true
		if r, ok := s.Report(st.ID); ok {
			s.watchServer(ctx, st, r)
		}
	}
	for id := range s.notified {
		if !present[id] {
			s.persist(ctx, id, nil)
		}
	}
}

func (s *Service) watchServer(ctx context.Context, st fleet.ServerState, r Report) {
	prev, next := s.notified[st.ID], map[string]string{}
	var fresh []notify.SecurityFinding
	freshIDs := map[string]bool{}
	open := 0
	for _, f := range r.Findings {
		key := itemFinding + f.Check.ID
		switch {
		case f.Accepted != nil:
			continue
		case f.Result == Unknown || f.Result == CantRead:
			// A gap (a probe hiccup, a refused read) says nothing: what was notified stays
			// notified, so the finding is not reported again when it is readable.
			if v, ok := prev[key]; ok {
				next[key] = v
			}
			continue
		case !f.Result.Problem():
			continue // pass or info: resolved, forgotten
		}
		open++
		next[key] = string(f.Result) + "|" + f.SubjectHash
		if isNew(prev[key], f) {
			fresh = append(fresh, notify.SecurityFinding{Title: f.Check.Title, Result: f.Result.Label(), Fail: f.Result == Fail})
			freshIDs[f.Check.ID] = true
		}
	}
	reminders := s.certReminders(st, r, prev, next, freshIDs)
	if !maps.Equal(prev, next) {
		s.persist(ctx, st.ID, next)
	}
	now := s.cfg.Now()
	if len(fresh) > 0 {
		s.emit(notify.SecurityEvent(notify.SecurityChange{ServerID: st.ID, ServerName: s.name(st.ID), New: fresh, Open: open}, now))
	}
	for _, rem := range reminders {
		s.emit(notify.CertExpiryEvent(rem, now))
	}
}

// isNew: never notified, another subject, or worse than what was notified.
func isNew(prev string, f Finding) bool {
	res, hash, ok := strings.Cut(prev, "|")
	return !ok || hash != f.SubjectHash || f.Result.Rank() > Result(res).Rank()
}

// sameCertificate: the VNC port presents the web port's certificate (iDRACs do).
func sameCertificate(p bmc.Posture) bool {
	return p.Web.Usable() && p.VNC.Usable() && p.VNC.Cert.SHA256 == p.Web.Cert.SHA256
}

// certReminders adds the reminder state of the web and VNC certificates to next and
// returns the reminders due: 14, 7 and 1 days before expiry, once each per certificate.
// A certificate whose expiry finding is accepted gets none; one whose finding was just
// notified as new has its reminder recorded without a second message; a VNC port that
// presents the web certificate is the same certificate, reminded once as the web one.
func (s *Service) certReminders(st fleet.ServerState, r Report, prev, next map[string]string,
	fresh map[string]bool) []notify.CertReminder {
	var out []notify.CertReminder
	for _, c := range []struct {
		port, check string
		probe       bmc.TLSProbe
	}{{"HTTPS", "tls.cert_expiry", st.Posture.Web}, {"VNC", "tls.vnc_cert", st.Posture.VNC}} {
		f, ok := r.Finding(c.check)
		if !ok || f.Accepted != nil || (c.port == "VNC" && sameCertificate(st.Posture)) {
			continue
		}
		if !c.probe.Usable() {
			// Not read this run (a timeout, a console session): keep what was already
			// reminded, so the next good read does not send the same reminder again.
			if v, seen := prev[itemCert+c.port]; seen {
				next[itemCert+c.port] = v
			}
			continue
		}
		days := c.probe.Cert.DaysLeft(s.cfg.Now())
		bucket := reminderBucket(days)
		if bucket == 0 {
			continue
		}
		key := itemCert + c.port
		next[key] = c.probe.Cert.SHA256 + "|" + itoa(bucket)
		if remindedAlready(prev[key], c.probe.Cert.SHA256, bucket) {
			continue
		}
		if !fresh[c.check] {
			out = append(out, notify.CertReminder{ServerID: st.ID, ServerName: s.name(st.ID), Port: c.port, Days: days,
				NotAfter: c.probe.Cert.NotAfter})
		}
	}
	return out
}

// remindedAlready: the same certificate was reminded at this bucket or a closer one.
func remindedAlready(prev, sha string, bucket int) bool {
	prevSHA, prevBucket, ok := strings.Cut(prev, "|")
	if !ok || prevSHA != sha {
		return false
	}
	n, err := strconv.Atoi(prevBucket)
	return err == nil && n <= bucket
}

// reminderBucket is the reminder a certificate with days left is in: 14, 7 or 1 (0: none,
// too far away or already expired, which the expiry check reports as a failure).
func reminderBucket(days int) int {
	switch {
	case days < 0:
		return 0
	case days <= 1:
		return 1
	case days <= 7:
		return 7
	case days <= 14:
		return 14
	default:
		return 0
	}
}

// persist replaces a server's bookkeeping rows (nil: drops them). The in-memory copy is
// updated even when the write fails, so a message is never repeated within a process.
func (s *Service) persist(ctx context.Context, id string, next map[string]string) {
	rows := make([]store.SecurityNotifiedRow, 0, len(next))
	now := s.cfg.Now().UTC()
	for k, v := range next {
		rows = append(rows, store.SecurityNotifiedRow{ServerID: id, Item: k, Value: v, NotifiedAt: now})
	}
	if err := s.cfg.DB.Security().SetNotified(ctx, id, rows); err != nil {
		s.cfg.Logger.Error("bmcsec: saving the notification state failed", "server", id, "err", err)
	}
	if len(next) == 0 {
		delete(s.notified, id)
		return
	}
	s.notified[id] = next
}

func (s *Service) emit(e notify.Event) {
	if s.cfg.Emit != nil {
		s.cfg.Emit(e)
	}
}

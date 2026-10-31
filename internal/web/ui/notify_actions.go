package ui

import (
	"net/http"
	"net/url"

	"oob-manager/internal/admin"
	"oob-manager/internal/authz"
	"oob-manager/internal/notify"
)

// deleteTargetSpec is the confirm page for deleting a browser-managed target.
func (s *server) deleteTargetSpec(r *http.Request, _ session) (confirmView, error) {
	if s.d.Notifications == nil {
		return confirmView{}, admin.ErrNotFound
	}
	tv, ok := s.d.Notifications.Target(r.PathValue("id"))
	if !ok || tv.Target.Source == notify.SourceFile || s.d.Notifications.Locked() {
		return confirmView{}, admin.ErrNotFound
	}
	t := tv.Target
	return confirmView{Title: "Delete notification target " + t.Name + "?", Badge: irreversible, Heading: "What happens",
		Consequences: []string{"Nothing more is sent to this " + t.Kind.Label() + " target.",
			"Its stored secrets are deleted. To send there again, add the target and enter them again."},
		Facts:  []kv{{"Kind", t.Kind.Label()}, {"Host", t.Host()}, {"Events", subsText(t)}},
		Button: "Delete " + t.Name, CancelHref: "/settings/notifications",
		ActionLabel: "Delete notification target · " + t.Name}, nil
}

func (s *server) deleteTarget(w http.ResponseWriter, r *http.Request, sess session, _ url.Values) {
	err := s.d.Notifications.Delete(r.Context(), actor(r, sess), r.PathValue("id"))
	if err != nil {
		s.targetFailed(w, r, sess, notify.TargetView{}, false, err)
		return
	}
	http.Redirect(w, r, "/settings/notifications?done=notify-deleted", http.StatusSeeOther)
}

// notifyFailing is the Overview banner: target names that keep failing.
func (s *server) notifyFailing(sess session) ([]string, bool) {
	if s.d.Notifications == nil {
		return nil, false
	}
	isAdmin := s.d.Authorize(sess.id.Principal(), authz.AdminNotifications, true) == nil
	return s.d.Notifications.Failing(), isAdmin
}

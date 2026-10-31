package ui

import (
	"context"
	"net/http"
	"strings"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/authz"
	"oob-manager/internal/notify"
)

// Notifications is the notifications service (*notify.Service, tech_doc §26). Every
// change it makes is audited; the UI authorizes (and step-up-checks target changes)
// before calling. Nothing it returns contains a secret.
type Notifications interface {
	Targets() []notify.TargetView
	Target(id string) (notify.TargetView, bool)
	Shadowed() []string
	Failing() []string
	Locked() bool
	Create(ctx context.Context, a admin.Actor, t notify.Target, s notify.Secrets) error
	Update(ctx context.Context, a admin.Actor, t notify.Target, s notify.Secrets, clearSecrets bool) error
	Delete(ctx context.Context, a admin.Actor, id string) error
	SendTest(ctx context.Context, a admin.Actor, id string) error
}

// Test sends are limited per user (security research F1: 3/min).
var notifyTestRate = RateLimit{Events: 3, Per: time.Minute}

// notifyRoutes is Settings → Notifications.
func (s *server) notifyRoutes(mux *http.ServeMux) {
	mux.Handle("GET /settings/notifications", s.notifyView(s.notifyPage))
	mux.Handle("GET /settings/notifications/new", s.notifyView(s.notifyNewPage))
	mux.Handle("POST /settings/notifications", s.change(authz.AdminNotificationsManage, backToNotify, s.createTarget))
	mux.Handle("GET /settings/notifications/{id}", s.notifyView(s.notifyEditPage))
	mux.Handle("POST /settings/notifications/{id}", s.change(authz.AdminNotificationsManage, backToTarget, s.updateTarget))
	mux.Handle("POST /settings/notifications/{id}/test", s.change(authz.AdminNotificationsManage, backToNotify, s.testTarget))
	mux.Handle("GET /settings/notifications/{id}/delete", s.notifyView(s.confirmPage(s.deleteTargetSpec)))
	mux.Handle("POST /settings/notifications/{id}/delete", s.confirmed(authz.AdminNotificationsManage, s.deleteTargetSpec, s.deleteTarget))
}

// notifyView is a read-only Notifications page: authenticated, authorized and only when
// the notifications service is wired.
func (s *server) notifyView(h pageHandler) http.Handler {
	return s.settingsView(authz.AdminNotifications, func(w http.ResponseWriter, r *http.Request, sess session) {
		if s.d.Notifications == nil {
			s.errorPage(w, r, http.StatusNotFound, "Notifications are not available in this installation.")
			return
		}
		h(w, r, sess)
	})
}

func backToNotify(*http.Request) string { return "/settings/notifications" }

func backToTarget(r *http.Request) string {
	return "/settings/notifications/" + validTargetID(r.PathValue("id"))
}

func backToServerPage(r *http.Request) string {
	id := r.PathValue("id")
	if !serverIDPattern.MatchString(id) {
		return "/"
	}
	// Acknowledgements are made on the Events tab; maintenance and notes on Activity.
	if strings.Contains(r.URL.Path, "/acks") {
		return "/servers/" + id + "/events"
	}
	return "/servers/" + id + "/activity"
}

// validTargetID returns id when it has the shape of a target id ("" otherwise), so it
// can be placed in a path.
func validTargetID(id string) string {
	if serverIDPattern.MatchString(id) {
		return id
	}
	return ""
}

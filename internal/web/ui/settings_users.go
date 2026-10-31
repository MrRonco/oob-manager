package ui

import (
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"oob-manager/internal/admin"
	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
)

type roleOption struct {
	Value, Label, Hint string
	Selected           bool
}

func roleOptions(selected authz.Role) []roleOption {
	out := make([]roleOption, 0, 3)
	for _, r := range []struct {
		role        authz.Role
		label, hint string
	}{{authz.RoleViewer, "Viewer", "Read only: health, logs, inventory."},
		{authz.RoleOperator, "Operator", "Graceful power and fan lease (as they arrive)."},
		{authz.RoleAdmin, "Admin", "Everything, including forced power, the graphical and serial consoles and Settings."}} {
		out = append(out, roleOption{Value: string(r.role), Label: r.label, Hint: r.hint, Selected: r.role == selected})
	}
	return out
}

type userRowView struct {
	ID, Username, Role, Status, StatusClass, Sessions, Created string
	Self, Disabled                                             bool
}

type usersView struct {
	StepUp    stepUpNote
	CSRF      string
	Rows      []userRowView
	Roles     []roleOption
	Username  string // refill after an error
	FormError string
}

type sessionView struct {
	ID, Short, Created, LastSeen, IP, UserAgent string
	Current, Pending                            bool
}

type userView struct {
	StepUp   stepUpNote
	CSRF     string
	User     userRowView
	Roles    []roleOption
	Sessions []sessionView
}

func (s *server) userRow(u admin.UserRow, self string, tf timeFmt) userRowView {
	v := userRowView{ID: u.ID, Username: u.Username, Role: string(u.Role), Sessions: strconv.Itoa(u.Sessions),
		Created: tf.full(u.CreatedAt), Self: u.ID == self, Disabled: u.Disabled}
	switch {
	case u.Disabled:
		v.Status, v.StatusClass = "Disabled", "unknown"
	case !u.Enrolled && !u.PendingLink.IsZero():
		v.Status, v.StatusClass = "Enrollment pending (link valid until "+tf.full(u.PendingLink)+")", "warn"
	case !u.Enrolled:
		v.Status, v.StatusClass = "Not enrolled: the link expired. Issue a new one.", "warn"
	default:
		v.Status, v.StatusClass = "Active", "ok"
	}
	return v
}

func (s *server) usersPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderUsers(w, r, sess, http.StatusOK, "", "")
}

func (s *server) renderUsers(w http.ResponseWriter, r *http.Request, sess session, status int, formErr, username string) {
	list, err := s.d.Admin.Users(r.Context())
	if err != nil {
		s.failChange(w, r, err)
		return
	}
	v := usersView{StepUp: s.stepUpNoteFor(r, sess), CSRF: s.csrf.issue(formSettings, sessionBinding(sess.token)),
		Roles: roleOptions(authz.RoleViewer), Username: safeUsername(username), FormError: formErr}
	for _, u := range list {
		v.Rows = append(v.Rows, s.userRow(u, sess.id.User.ID, sess.tf()))
	}
	v.StepUp.Next = "/settings/users"
	s.render(w, r, status, pageSettingsUsers, s.settingsLayout(r, sess, "Users", v))
}

func (s *server) userPage(w http.ResponseWriter, r *http.Request, sess session) {
	u, ok := s.lookupUser(w, r)
	if !ok {
		return
	}
	list, err := s.d.Admin.Sessions(r.Context(), u.ID)
	if err != nil {
		s.failChange(w, r, err)
		return
	}
	current := hex.EncodeToString(sess.id.Session.IDHash)
	v := userView{StepUp: s.stepUpNoteFor(r, sess), CSRF: s.csrf.issue(formSettings, sessionBinding(sess.token)),
		User: s.userRow(u, sess.id.User.ID, sess.tf()), Roles: roleOptions(u.Role)}
	for _, x := range list {
		v.Sessions = append(v.Sessions, sessionView{ID: x.ID, Short: x.ID[:8], Created: sess.tf().full(x.CreatedAt),
			LastSeen: sess.tf().full(x.LastSeen), IP: x.IP, UserAgent: x.UserAgent,
			Current: x.ID == current, Pending: x.Pending})
	}
	d := s.settingsLayout(r, sess, u.Username, v)
	d.Crumbs = []crumb{{"Settings", "/settings"}, {"Users", "/settings/users"}, {Label: u.Username}}
	s.render(w, r, http.StatusOK, pageSettingsUser, d)
}

// userIDPattern matches the 128-bit hex IDs the auth package generates.
func validUserID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 16
}

func (s *server) lookupUser(w http.ResponseWriter, r *http.Request) (admin.UserRow, bool) {
	id := r.PathValue("id")
	if !validUserID(id) {
		s.errorPage(w, r, http.StatusNotFound, "No user with that ID.")
		return admin.UserRow{}, false
	}
	u, err := s.d.Admin.User(r.Context(), id)
	if errors.Is(err, admin.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No user with that ID.")
		return admin.UserRow{}, false
	}
	if err != nil {
		s.failChange(w, r, err)
		return admin.UserRow{}, false
	}
	return u, true
}

func backToUsers(*http.Request) string { return "/settings/users" }

// userURL is a user's settings page with a confirmation key; a malformed ID falls back
// to the user list, so nothing but a re-encoded hex ID reaches a Location header.
func userURL(id, done string) string {
	b, err := hex.DecodeString(id)
	if err != nil || len(b) != 16 || doneMessage(done) == "" {
		return "/settings/users"
	}
	return "/settings/users/" + hex.EncodeToString(b) + "?done=" + done
}

func backToUser(r *http.Request) string {
	if id := r.PathValue("id"); validUserID(id) {
		return "/settings/users/" + id
	}
	return "/settings/users"
}

// createUser adds an account and shows its one-time enrolment link (200, no-store).
func (s *server) createUser(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	username, role := form.Get("username"), authz.Role(form.Get("role"))
	link, err := s.d.Admin.CreateUser(r.Context(), actor(r, sess), username, role)
	if err != nil {
		status, msg := s.adminError(err)
		s.renderUsers(w, r, sess, status, msg, username)
		return
	}
	s.renderLink(w, r, sess, link, "User created")
}

func (s *server) setRole(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	id := r.PathValue("id")
	if u, err := s.d.Admin.User(r.Context(), id); err == nil && string(u.Role) == form.Get("role") {
		redirectLocal(w, r, userURL(id, "role-unchanged"))
		return
	}
	if err := s.d.Admin.SetRole(r.Context(), actor(r, sess), id, authz.Role(form.Get("role"))); err != nil {
		s.failChange(w, r, err)
		return
	}
	redirectLocal(w, r, userURL(id, "role"))
}

func (s *server) setDisabled(disabled bool) changeHandler {
	return func(w http.ResponseWriter, r *http.Request, sess session, _ url.Values) {
		id := r.PathValue("id")
		if err := s.d.Admin.SetDisabled(r.Context(), actor(r, sess), id, disabled); err != nil {
			s.failChange(w, r, err)
			return
		}
		done := "enabled"
		if disabled {
			done = "disabled"
		}
		redirectLocal(w, r, userURL(id, done))
	}
}

func (s *server) resetTOTP(w http.ResponseWriter, r *http.Request, sess session, _ url.Values) {
	link, err := s.d.Admin.ResetEnrolment(r.Context(), actor(r, sess), r.PathValue("id"))
	if err != nil {
		s.failChange(w, r, err)
		return
	}
	s.renderLink(w, r, sess, link, "Authenticator reset")
}

func (s *server) revokeSession(w http.ResponseWriter, r *http.Request, sess session, _ url.Values) {
	id := r.PathValue("id")
	if err := s.d.Admin.RevokeSession(r.Context(), actor(r, sess), id, r.PathValue("sid")); err != nil {
		s.failChange(w, r, err)
		return
	}
	s.afterRevoke(w, r, sess, id, "revoked")
}

func (s *server) revokeAll(w http.ResponseWriter, r *http.Request, sess session, _ url.Values) {
	id := r.PathValue("id")
	if _, err := s.d.Admin.RevokeSessions(r.Context(), actor(r, sess), id); err != nil {
		s.failChange(w, r, err)
		return
	}
	s.afterRevoke(w, r, sess, id, "revoked-all")
}

// afterRevoke returns to the user page, or to sign-in when the admin ended their own
// current session.
func (s *server) afterRevoke(w http.ResponseWriter, r *http.Request, sess session, id, done string) {
	if _, err := s.d.Auth.Authenticate(r.Context(), sess.token); err != nil {
		http.SetCookie(w, auth.ClearSessionCookie())
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	redirectLocal(w, r, userURL(id, done))
}

package ui

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"oob-manager/internal/notify"
	"oob-manager/internal/secrets"
)

// notifyFormView is the add/edit form of one target kind (the wizard's second step).
type notifyFormView struct {
	StepUp            stepUpNote
	CSRF              string
	New               bool
	Action            string
	Kind              string
	KindLabel         string
	KindHelp          string
	ID, Name, URL     string
	Enabled           bool
	AllowPlaintext    bool
	IncludeDetail     bool
	PushoverEmergency bool
	Classes           []classOption
	Severities        []sevOption
	SMTPHost          string
	SMTPPort          string
	EmailSecurity     string
	EmailFrom         string
	EmailTo           string
	// Secret state: never the value, only whether one is stored and its version.
	SecretNote     string
	SecretOptional bool
	FormError      string
	CanDelete      bool
}

type classOption struct {
	Value, Label string
	Checked      bool
	// New marks a class added after targets may already exist (bmc, tech_doc §37): a
	// target saved before it lists its classes explicitly and is not subscribed.
	New bool
}

type sevOption struct {
	Value, Label string
	Selected     bool
}

func classOptions(selected []notify.Class) []classOption {
	out := make([]classOption, 0, len(notify.Classes()))
	for _, c := range notify.Classes() {
		out = append(out, classOption{Value: string(c), Label: c.Label(), Checked: slices.Contains(selected, c),
			New: c == notify.ClassBMC})
	}
	return out
}

func sevOptions(selected notify.Severity) []sevOption {
	labels := map[notify.Severity]string{notify.SeverityInfo: "Info and above (everything)",
		notify.SeverityWarning: "Warning and above", notify.SeverityCritical: "Critical only"}
	out := make([]sevOption, 0, 3)
	for _, s := range notify.Severities() {
		out = append(out, sevOption{Value: s.String(), Label: labels[s], Selected: s == selected})
	}
	return out
}

// notifyNewPage is the wizard: without ?kind it lists the kinds; with one it shows that
// kind's form with safe defaults (warning and above, every class, no BMC text).
func (s *server) notifyNewPage(w http.ResponseWriter, r *http.Request, sess session) {
	if s.d.Notifications.Locked() {
		s.errorPage(w, r, http.StatusForbidden, "Notification targets are managed by config.yaml here.")
		return
	}
	kind, err := notify.ParseKind(r.URL.Query().Get("kind"))
	if err != nil {
		http.Redirect(w, r, "/settings/notifications#add", http.StatusSeeOther)
		return
	}
	t := notify.Target{Kind: kind, Enabled: true, Classes: notify.Classes(), MinSeverity: notify.SeverityWarning,
		EmailSecurity: notify.EmailSTARTTLS}
	if kind == notify.KindPushover {
		t.URL = notify.DefaultPushoverURL
	}
	s.renderNotifyForm(w, r, sess, http.StatusOK, s.formOf(notify.TargetView{Target: t}, true), "")
}

func (s *server) notifyEditPage(w http.ResponseWriter, r *http.Request, sess session) {
	tv, ok := s.d.Notifications.Target(r.PathValue("id"))
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "There is no such notification target.")
		return
	}
	if tv.Target.Source == notify.SourceFile || s.d.Notifications.Locked() {
		s.errorPage(w, r, http.StatusForbidden, "This target is managed by config.yaml. Edit the file and restart.")
		return
	}
	s.renderNotifyForm(w, r, sess, http.StatusOK, s.formOf(tv, false), "")
}

// formOf fills the form from a target (never from its secrets).
func (s *server) formOf(tv notify.TargetView, isNew bool) notifyFormView {
	t := tv.Target
	v := notifyFormView{New: isNew, Kind: string(t.Kind), KindLabel: t.Kind.Label(), KindHelp: kindHelp(t.Kind),
		ID: t.ID, Name: t.Name, URL: t.URL, Enabled: t.Enabled, AllowPlaintext: t.AllowPlaintext,
		IncludeDetail: t.IncludeDetail, PushoverEmergency: t.PushoverEmergency, Classes: classOptions(t.Classes),
		Severities: sevOptions(t.MinSeverity), EmailSecurity: string(t.EmailSecurity), EmailFrom: t.EmailFrom,
		EmailTo: strings.Join(t.EmailTo, ", "), CanDelete: !isNew,
		SecretOptional: t.Kind == notify.KindNtfy || t.Kind == notify.KindWebhook || t.Kind == notify.KindEmail}
	if t.Kind == notify.KindEmail && t.URL != "" {
		if u, err := url.Parse(t.URL); err == nil {
			v.SMTPHost, v.SMTPPort = u.Hostname(), u.Port()
		}
		v.URL = ""
	}
	if v.SMTPPort == "" {
		v.SMTPPort = "587"
	}
	if !isNew {
		v.SecretNote = secretNote(tv)
	}
	return v
}

func (s *server) renderNotifyForm(w http.ResponseWriter, r *http.Request, sess session, status int, v notifyFormView,
	formErr string) {
	v.StepUp, v.CSRF, v.FormError = s.stepUpNoteFor(r, sess), s.csrf.issue(formSettings, sessionBinding(sess.token)), formErr
	v.Action = "/settings/notifications"
	title := "Add " + v.KindLabel + " target"
	if !v.New {
		v.Action += "/" + v.ID
		title = "Edit " + v.Name
	}
	v.StepUp.Next = r.URL.Path
	noStore(w)
	d := s.settingsLayout(r, sess, title, v)
	d.Crumbs = []crumb{{"Settings", "/settings"}, {"Notifications", "/settings/notifications"}, {Label: title}}
	s.render(w, r, status, pageSettingsNotifyForm, d)
}

// targetForm reads the form into a target and its secrets. Values are validated by
// notify.Validate in the service; this only maps fields and closed enums.
func targetForm(kind notify.Kind, form url.Values) (notify.Target, notify.Secrets, bool, error) {
	t := notify.Target{Kind: kind, ID: strings.TrimSpace(form.Get("id")), Name: strings.TrimSpace(form.Get("name")),
		URL: strings.TrimSpace(form.Get("url")), Enabled: form.Get("enabled") == "on",
		AllowPlaintext: form.Get("allow_plaintext") == "on", IncludeDetail: form.Get("include_detail") == "on",
		PushoverEmergency: form.Get("pushover_emergency") == "on"}
	for _, c := range form["classes"] {
		cl, err := notify.ParseClass(c)
		if err != nil {
			return notify.Target{}, notify.Secrets{}, false, fmt.Errorf("%w: unknown event class", notify.ErrInvalid)
		}
		t.Classes = append(t.Classes, cl)
	}
	sev, err := notify.ParseSeverity(form.Get("min_severity"))
	if err != nil {
		return notify.Target{}, notify.Secrets{}, false, fmt.Errorf("%w: choose a minimum severity", notify.ErrInvalid)
	}
	t.MinSeverity = sev
	if kind == notify.KindEmail {
		t = emailForm(t, form)
	}
	sec := notify.Secrets{Token: formSecret(form, "token"), User: formSecret(form, "user"),
		Password: formSecret(form, "password")}
	return t, sec, form.Get("clear_secrets") == "on", nil
}

func emailForm(t notify.Target, form url.Values) notify.Target {
	host := strings.TrimSpace(form.Get("smtp_host"))
	port := strings.TrimSpace(form.Get("smtp_port"))
	t.URL = "smtp://" + net.JoinHostPort(host, port)
	t.EmailSecurity = notify.EmailSecurity(form.Get("email_security"))
	t.EmailFrom = strings.TrimSpace(form.Get("email_from"))
	t.EmailTo = strings.FieldsFunc(form.Get("email_to"), func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\r'
	})
	return t
}

func formSecret(form url.Values, key string) secrets.Secret {
	v := form.Get(key)
	if v == "" {
		return secrets.Secret{}
	}
	return secrets.New(v)
}

func (s *server) createTarget(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	if s.d.Notifications == nil {
		s.errorPage(w, r, http.StatusNotFound, "Notifications are not available in this installation.")
		return
	}
	kind, err := notify.ParseKind(form.Get("kind"))
	if err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "Choose a target kind.")
		return
	}
	t, sec, _, err := targetForm(kind, form)
	if err == nil {
		err = s.d.Notifications.Create(r.Context(), actor(r, sess), t, sec)
	}
	if err == nil {
		http.Redirect(w, r, "/settings/notifications?done=notify-created", http.StatusSeeOther)
		return
	}
	s.targetFailed(w, r, sess, notify.TargetView{Target: t}, true, err)
}

func (s *server) updateTarget(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	if s.d.Notifications == nil {
		s.errorPage(w, r, http.StatusNotFound, "Notifications are not available in this installation.")
		return
	}
	cur, ok := s.d.Notifications.Target(r.PathValue("id"))
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "There is no such notification target.")
		return
	}
	t, sec, clearSec, err := targetForm(cur.Target.Kind, form)
	t.ID = cur.Target.ID
	if err == nil {
		err = s.d.Notifications.Update(r.Context(), actor(r, sess), t, sec, clearSec)
	}
	if err == nil {
		http.Redirect(w, r, "/settings/notifications?done=notify-saved", http.StatusSeeOther)
		return
	}
	cur.Target = mergeShown(cur.Target, t)
	s.targetFailed(w, r, sess, cur, false, err)
}

// mergeShown re-fills the form with what was submitted (never secrets).
func mergeShown(cur, sub notify.Target) notify.Target {
	sub.Source, sub.SecretVersion, sub.Kind = cur.Source, cur.SecretVersion, cur.Kind
	return sub
}

// targetFailed maps a refused change to a status and re-renders the form (422) or an
// error page.
func (s *server) targetFailed(w http.ResponseWriter, r *http.Request, sess session, tv notify.TargetView, isNew bool, err error) {
	switch {
	case errors.Is(err, notify.ErrInvalid):
		msg := strings.TrimPrefix(err.Error(), notify.ErrInvalid.Error()+": ")
		s.renderNotifyForm(w, r, sess, http.StatusUnprocessableEntity, s.formOf(tv, isNew), "Not saved: "+msg)
	case errors.Is(err, notify.ErrExists):
		s.renderNotifyForm(w, r, sess, http.StatusConflict, s.formOf(tv, isNew), "Not saved: a target with this id already exists.")
	case errors.Is(err, notify.ErrLocked):
		s.errorPage(w, r, http.StatusForbidden, "This target is managed by config.yaml or the section is locked. Nothing was changed.")
	case errors.Is(err, notify.ErrNotFound):
		s.errorPage(w, r, http.StatusNotFound, "There is no such notification target.")
	default:
		s.d.Logger.Error("ui notification target change failed", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "The target could not be saved. Nothing was changed.")
	}
}

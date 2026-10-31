package ui

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/notify"
)

// notifyListView is Settings → Notifications.
type notifyListView struct {
	StepUp   stepUpNote
	CSRF     string
	Locked   bool
	CanEdit  bool
	Rows     []notifyRow
	Shadowed []string
	Kinds    []notifyKindOption
}

// notifyRow is one target with its delivery state. Only the host of the URL is shown
// (an ntfy topic or webhook path can act as a credential).
type notifyRow struct {
	ID, Name, Kind, Host, Subs     string
	FileManaged, Enabled           bool
	Status                         healthView
	StatusText                     string
	LastSuccess, LastSuccessISO    string
	LastFailure, LastFailureISO    string
	LastError, SecretNote, Dropped string
}

type notifyKindOption struct {
	Value, Label, Help string
}

// kindHelp says what each kind needs (shown on the chooser and the form).
func kindHelp(k notify.Kind) string {
	switch k {
	case notify.KindNtfy:
		return "A topic URL on ntfy.sh or your own ntfy server, and an access token if the topic is protected."
	case notify.KindPushover:
		return "A Pushover application token and your user key."
	case notify.KindGotify:
		return "Your Gotify server URL and an application token."
	case notify.KindWebhook:
		return "Any HTTPS endpoint that accepts the documented JSON body (version 1), optionally signed with HMAC-SHA256."
	case notify.KindEmail:
		return "An SMTP server (STARTTLS or TLS), a sender and up to 10 recipients."
	default:
		return ""
	}
}

func notifyKindOptions() []notifyKindOption {
	out := make([]notifyKindOption, 0, len(notify.Kinds()))
	for _, k := range notify.Kinds() {
		out = append(out, notifyKindOption{Value: string(k), Label: k.Label(), Help: kindHelp(k)})
	}
	return out
}

func (s *server) notifyPage(w http.ResponseWriter, r *http.Request, sess session) {
	n := s.d.Notifications
	v := notifyListView{StepUp: s.stepUpNoteFor(r, sess), CSRF: s.csrf.issue(formSettings, sessionBinding(sess.token)),
		Locked: n.Locked(), Shadowed: n.Shadowed(), Kinds: notifyKindOptions()}
	v.CanEdit = !v.Locked
	v.StepUp.Next = "/settings/notifications"
	for _, tv := range n.Targets() {
		v.Rows = append(v.Rows, s.notifyRowOf(tv, sess.tf()))
	}
	d := s.settingsLayout(r, sess, "Notifications", v)
	if key := r.URL.Query().Get("done"); notifyDone(key) != "" {
		d.Flash, d.FlashKind = notifyDone(key), "info"
		if strings.HasPrefix(key, "notify-test-failed-") {
			d.FlashKind = "error"
		}
	}
	s.render(w, r, http.StatusOK, pageSettingsNotify, d)
}

func (s *server) notifyRowOf(tv notify.TargetView, tf timeFmt) notifyRow {
	t, st := tv.Target, tv.Status
	row := notifyRow{ID: t.ID, Name: t.Name, Kind: t.Kind.Label(), Host: t.Host(), Enabled: t.Enabled,
		FileManaged: t.Source == notify.SourceFile, Subs: subsText(t), LastError: st.LastError}
	switch {
	case !t.Enabled:
		row.Status, row.StatusText = healthView{Class: "stale", Label: "Off"}, "Off"
	case st.Failing:
		row.Status, row.StatusText = healthView{Class: "crit", Label: "Failing"}, "Failing"
	case st.LastSuccess.IsZero() && st.LastFailure.IsZero():
		row.Status, row.StatusText = healthView{Class: "info", Label: "Nothing sent yet"}, "Nothing sent yet"
	case st.ConsecutiveFailures > 0:
		row.Status, row.StatusText = healthView{Class: "warn", Label: "Last send failed"}, "Last send failed"
	default:
		row.Status, row.StatusText = healthView{Class: "ok", Label: "Working"}, "Working"
	}
	if !st.LastSuccess.IsZero() {
		row.LastSuccess, row.LastSuccessISO = tf.full(st.LastSuccess), isoUTC(st.LastSuccess)
	}
	if !st.LastFailure.IsZero() {
		row.LastFailure, row.LastFailureISO = tf.full(st.LastFailure), isoUTC(st.LastFailure)
	}
	if st.Dropped > 0 {
		row.Dropped = formatCount(st.Dropped)
	}
	row.SecretNote = secretNote(tv)
	return row
}

func secretNote(tv notify.TargetView) string {
	switch {
	case tv.SecretError:
		return "Stored secret cannot be opened: enter it again"
	case tv.HasSecret && tv.Target.Source == notify.SourceFile:
		return "Secret from the credential file"
	case tv.HasSecret:
		return "Secret set · v" + strconv.Itoa(tv.Target.SecretVersion)
	default:
		return "No secret"
	}
}

// subsText summarises a subscription ("All events · warning and above").
func subsText(t notify.Target) string {
	what := "No events"
	switch n := len(t.Classes); {
	case n == len(notify.Classes()):
		what = "All events"
	case n > 0:
		labels := make([]string, 0, n)
		for _, c := range t.Classes {
			labels = append(labels, string(c))
		}
		what = strings.Join(labels, ", ")
	}
	sev := map[notify.Severity]string{notify.SeverityInfo: "everything", notify.SeverityWarning: "warning and above",
		notify.SeverityCritical: "critical only"}[t.MinSeverity]
	return what + " · " + sev
}

// testTarget sends a test message now and reports the class of any failure.
func (s *server) testTarget(w http.ResponseWriter, r *http.Request, sess session, _ url.Values) {
	if s.d.Notifications == nil {
		s.errorPage(w, r, http.StatusNotFound, "Notifications are not available in this installation.")
		return
	}
	if ok, wait := s.notifyLimit.allow("user:" + sess.id.User.ID); !ok {
		s.deny(r, sess, "admin.notify.test", "rate_limited")
		setRetryAfter(w, wait)
		s.errorPage(w, r, http.StatusTooManyRequests, "Three tests a minute at most. "+tryAgainIn(wait))
		return
	}
	id := validTargetID(r.PathValue("id"))
	err := s.d.Notifications.SendTest(r.Context(), actor(r, sess), id)
	switch {
	case err == nil:
		http.Redirect(w, r, "/settings/notifications?done=notify-test", http.StatusSeeOther)
	case errors.Is(err, notify.ErrNotFound):
		s.errorPage(w, r, http.StatusNotFound, "There is no such notification target.")
	default:
		redirectLocal(w, r, "/settings/notifications?done=notify-test-failed-"+notifyErrorKey(err))
	}
}

// notifyErrorKey is a closed set of failure keys for the result message.
func notifyErrorKey(err error) string {
	switch c := notify.ErrorClass(err); c {
	case "blocked", "dns", "timeout", "tls", "network", "redirect", "http_4xx", "http_5xx", "rate_limited", "smtp", "secrets":
		return c
	default:
		return "network"
	}
}

// notifyDone is the result message of ?done= on the Notifications page.
func notifyDone(key string) string {
	if !strings.HasPrefix(key, "notify-test-failed-") {
		return map[string]string{
			"notify-created": "Target added. Send a test to check it.",
			"notify-saved":   "Target saved.",
			"notify-same":    "Nothing changed.",
			"notify-deleted": "Target deleted.",
			"notify-test":    "Test sent. The receiver accepted it.",
		}[key]
	}
	why := map[string]string{ //nolint:gosec // G101: failure descriptions, not credentials
		"blocked":      "the destination is not allowed (a private address needs notifications.allowed_networks; plaintext needs it too)",
		"dns":          "the host name did not resolve",
		"timeout":      "the receiver did not answer in time",
		"tls":          "the TLS certificate was not trusted or STARTTLS was not offered",
		"network":      "the connection failed",
		"redirect":     "the receiver answered with a redirect, which is never followed",
		"http_4xx":     "the receiver refused it (check the token, key or URL)",
		"http_5xx":     "the receiver had an error",
		"rate_limited": "the receiver rate limited it",
		"smtp":         "the mail server refused it",
		"secrets":      "the stored secret cannot be opened; enter it again",
	}[strings.TrimPrefix(key, "notify-test-failed-")]
	if why == "" {
		return ""
	}
	return "Test failed: " + why + "."
}

func isoUTC(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func formatCount(n uint64) string { return strconv.FormatUint(n, 10) }

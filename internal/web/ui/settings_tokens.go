package ui

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/auth"
)

// expiryOptions are the token lifetimes offered (a closed set; the CLI accepts any
// value within auth.MinTokenLifetime..MaxTokenLifetime).
var expiryDays = []int{0, 7, 30, 90, 365, 730}

type expiryOption struct {
	Value, Label string
	Selected     bool
}

func expiryOptions(selected int) []expiryOption {
	out := make([]expiryOption, 0, len(expiryDays))
	for _, d := range expiryDays {
		label := "Never expires"
		if d > 0 {
			label = strconv.Itoa(d) + " days"
		}
		out = append(out, expiryOption{Value: strconv.Itoa(d), Label: label, Selected: d == selected})
	}
	return out
}

func parseExpiry(s string) (time.Duration, bool) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	for _, d := range expiryDays {
		if d == n {
			return time.Duration(d) * 24 * time.Hour, true
		}
	}
	return 0, false
}

type tokenRowView struct {
	ID, Name, Owner, Created, LastUsed, Expires, Status, StatusClass string
	Active                                                           bool
}

type tokensView struct {
	StepUp    stepUpNote
	CSRF      string
	Rows      []tokenRowView
	Expiries  []expiryOption
	Name      string
	FormError string
}

func (s *server) tokensPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderTokens(w, r, sess, http.StatusOK, "", "")
}

func (s *server) renderTokens(w http.ResponseWriter, r *http.Request, sess session, status int, formErr, name string) {
	list, err := s.d.Admin.Tokens(r.Context())
	if err != nil {
		s.failChange(w, r, err)
		return
	}
	v := tokensView{StepUp: s.stepUpNoteFor(r, sess), CSRF: s.csrf.issue(formSettings, sessionBinding(sess.token)),
		Expiries: expiryOptions(90), Name: printableOnly(name), FormError: formErr}
	for _, t := range list {
		v.Rows = append(v.Rows, s.tokenRow(t, sess.tf()))
	}
	v.StepUp.Next = "/settings/tokens"
	s.render(w, r, status, pageSettingsTokens, s.settingsLayout(r, sess, "API tokens", v))
}

func (s *server) tokenRow(t admin.TokenRow, tf timeFmt) tokenRowView {
	v := tokenRowView{ID: t.ID, Name: t.Name, Owner: t.Owner, Created: tf.full(t.CreatedAt),
		LastUsed: "Never used", Expires: "Never", Status: string(t.Status), Active: t.Status == auth.TokenActive}
	if !t.LastUsedAt.IsZero() {
		v.LastUsed = tf.full(t.LastUsedAt)
	}
	if !t.ExpiresAt.IsZero() {
		v.Expires = tf.full(t.ExpiresAt)
	}
	switch t.Status {
	case auth.TokenActive:
		v.Status, v.StatusClass = "Active", "ok"
	case auth.TokenExpired:
		v.Status, v.StatusClass = "Expired", "warn"
	default:
		v.Status, v.StatusClass = "Revoked", "unknown"
	}
	return v
}

// printableOnly echoes a typed token name back into the form only when it is short
// and printable; html/template escapes it either way.
func printableOnly(s string) string {
	if len(s) > 64 || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return ""
	}
	return s
}

func backToTokens(*http.Request) string { return "/settings/tokens" }

// createToken mints a token and shows it once: a 200 page with Cache-Control no-store,
// never a redirect, so the secret is in exactly one response.
func (s *server) createToken(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	name := strings.TrimSpace(form.Get("name"))
	ttl, ok := parseExpiry(form.Get("expires"))
	if !ok {
		s.renderTokens(w, r, sess, http.StatusBadRequest, "Choose one of the offered lifetimes.", name)
		return
	}
	raw, tok, err := s.d.Admin.CreateToken(r.Context(), actor(r, sess), sess.id.User.ID, name, ttl)
	if err != nil {
		status, msg := s.adminError(err)
		s.renderTokens(w, r, sess, status, msg, name)
		return
	}
	expires := "never expires"
	if !tok.ExpiresAt.IsZero() {
		expires = "expires " + sess.tf().full(tok.ExpiresAt)
	}
	s.renderReveal(w, r, sess, revealView2{Heading: "Token created", Kind: "token", Secret: raw, Name: tok.Name,
		Detail: "Read-only API token, " + expires + ".", Back: "/settings/tokens", BackLabel: "Back to API tokens"})
}

func (s *server) revokeToken(w http.ResponseWriter, r *http.Request, sess session, _ url.Values) {
	if err := s.d.Admin.RevokeToken(r.Context(), actor(r, sess), r.PathValue("id")); err != nil {
		s.failChange(w, r, err)
		return
	}
	http.Redirect(w, r, "/settings/tokens?done=token-revoked", http.StatusSeeOther)
}

// revealView2 is the shown-once page for an API token or an enrolment link.
type revealView2 struct {
	Heading, Kind, Secret, Name, Detail, Back, BackLabel string
}

func (s *server) renderReveal(w http.ResponseWriter, r *http.Request, sess session, v revealView2) {
	noStore(w)
	s.render(w, r, http.StatusOK, pageSettingsReveal, s.settingsLayout(r, sess, v.Heading, v))
}

// renderLink shows a one-time enrolment link for the admin to hand over.
func (s *server) renderLink(w http.ResponseWriter, r *http.Request, sess session, link admin.Link, heading string) {
	s.renderReveal(w, r, sess, revealView2{Heading: heading, Kind: "link", Secret: s.linkURL(r, link.Token),
		Name: link.Username, Detail: "One-time enrollment link for " + link.Username + ", valid until " +
			sess.tf().full(link.ExpiresAt) + ". Opening it lets the user set a password and an authenticator.",
		Back: "/settings/users", BackLabel: "Back to users"})
}

// linkURL is the absolute enrolment URL. public_url wins; otherwise the request's host
// (the admin's own request, so the host is the one they reach the app on).
func (s *server) linkURL(r *http.Request, token string) string {
	base := strings.TrimRight(s.d.PublicURL, "/")
	if base == "" {
		base = "https://" + r.Host
	}
	return base + "/enroll/" + token
}

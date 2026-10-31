package ui

import (
	"net/http"
	"time"

	"oob-manager/internal/admin"
)

// recentUse is how recently a token must have been used for its revocation to need the
// typed name (UX-06: revoking a token in use breaks an integration).
const recentUse = 24 * time.Hour

var (
	reversible   = healthView{Label: "Reversible", Class: "info"}
	irreversible = healthView{Label: "Cannot be undone", Class: "crit"}
)

// userTarget looks up the user named by the path, as a confirm spec error when absent.
func (s *server) userTarget(r *http.Request) (admin.UserRow, error) {
	id := r.PathValue("id")
	if !validUserID(id) {
		return admin.UserRow{}, admin.ErrNotFound
	}
	return s.d.Admin.User(r.Context(), id)
}

func (s *server) disableSpec(r *http.Request, _ session) (confirmView, error) {
	u, err := s.userTarget(r)
	if err != nil {
		return confirmView{}, err
	}
	return confirmView{Title: "Disable account " + u.Username + "?", Badge: reversible, Tier: tierCaution, Heading: "What happens",
		Consequences: []string{u.Username + " is signed out everywhere and cannot sign in.",
			"Unused setup links for " + u.Username + " stop working.",
			"An admin can enable the account again later."},
		Button: "Disable " + u.Username, CancelHref: "/settings/users/" + u.ID,
		ActionLabel: "Disable account · " + u.Username}, nil
}

func (s *server) resetSpec(r *http.Request, _ session) (confirmView, error) {
	u, err := s.userTarget(r)
	if err != nil {
		return confirmView{}, err
	}
	return confirmView{Title: "Reset authenticator for " + u.Username + "?", Badge: irreversible, Tier: tierDanger, Heading: "What happens",
		Consequences: []string{u.Username + " is signed out everywhere.",
			"The current authenticator stops working.",
			"A new one-time setup link is created, which you send to " + u.Username + "."},
		Typed: u.Username, TypedWhy: "Resetting cannot be undone.",
		Button: "Reset authenticator for " + u.Username, CancelHref: "/settings/users/" + u.ID,
		ActionLabel: "Reset authenticator · " + u.Username}, nil
}

func (s *server) revokeAllSpec(r *http.Request, _ session) (confirmView, error) {
	u, err := s.userTarget(r)
	if err != nil {
		return confirmView{}, err
	}
	return confirmView{Title: "End all sessions of " + u.Username + "?", Badge: reversible, Tier: tierCaution, Heading: "What happens",
		Consequences: []string{"Every browser signed in as " + u.Username + " is signed out.",
			u.Username + " can sign in again with password and code."},
		Note:   "If you end your own sessions, you are signed out too.",
		Button: "End all sessions of " + u.Username, CancelHref: "/settings/users/" + u.ID,
		ActionLabel: "End all sessions · " + u.Username}, nil
}

func (s *server) revokeSessionSpec(r *http.Request, sess session) (confirmView, error) {
	u, err := s.userTarget(r)
	if err != nil {
		return confirmView{}, err
	}
	sid := r.PathValue("sid")
	list, err := s.d.Admin.Sessions(r.Context(), u.ID)
	if err != nil {
		return confirmView{}, err
	}
	for _, x := range list {
		if x.ID != sid {
			continue
		}
		short := x.ID[:min(len(x.ID), 8)]
		return confirmView{Title: "End session " + short + " of " + u.Username + "?", Badge: reversible, Tier: tierCaution, Heading: "What happens",
			Consequences: []string{"That browser is signed out.", u.Username + " can sign in again."},
			Facts:        []kv{{"Last seen", sess.tf().full(x.LastSeen)}, {"Address", x.IP}, {"Browser", x.UserAgent}},
			Button:       "End session " + short, CancelHref: "/settings/users/" + u.ID,
			ActionLabel: "End session · " + u.Username}, nil
	}
	return confirmView{}, admin.ErrNotFound
}

func (s *server) revokeTokenSpec(r *http.Request, sess session) (confirmView, error) {
	list, err := s.d.Admin.Tokens(r.Context())
	if err != nil {
		return confirmView{}, err
	}
	id := r.PathValue("id")
	for _, t := range list {
		if t.ID != id || s.tokenRow(t, sess.tf()).Status != "Active" {
			continue
		}
		row := s.tokenRow(t, sess.tf())
		v := confirmView{Title: "Revoke token " + t.Name + "?", Badge: irreversible, Tier: tierDanger, Heading: "What happens",
			Consequences: []string{"Anything that uses this token (a dashboard, a monitor, a script) stops getting data at once.",
				"The token cannot be restored; create a new one if you still need access."},
			Facts:  []kv{{"Last used", row.LastUsed}, {"Owner", t.Owner}, {"Expires", row.Expires}},
			Button: "Revoke token " + t.Name, CancelHref: "/settings/tokens", ActionLabel: "Revoke API token · " + t.Name}
		if !t.LastUsedAt.IsZero() && s.d.Now().Sub(t.LastUsedAt) < recentUse {
			v.Typed, v.TypedWhy = t.Name, "This token was used in the last 24 hours."
		}
		return v, nil
	}
	return confirmView{}, admin.ErrNotFound
}

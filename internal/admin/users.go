package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/store"
)

// UserRow is one account as the settings pages show it. It carries no secret.
type UserRow struct {
	ID          string
	Username    string
	Role        authz.Role
	Disabled    bool
	Enrolled    bool // authenticator confirmed; the account can sign in
	Sessions    int
	PendingLink time.Time // expiry of an unused enrolment link; zero when none
	CreatedAt   time.Time
}

// Link is a one-time enrolment link. Token is the secret part of the URL: show it once.
type Link struct {
	Token     string
	Username  string
	Purpose   store.EnrolPurpose
	ExpiresAt time.Time
}

// String keeps the secret out of logs and %v.
func (Link) String() string { return "admin.Link{[redacted]}" }

// Users lists every account (username order).
func (s *Service) Users(ctx context.Context) ([]UserRow, error) {
	users, err := s.cfg.DB.Users().List(ctx)
	if err != nil {
		return nil, err
	}
	counts, err := s.cfg.DB.Sessions().CountByUser(ctx)
	if err != nil {
		return nil, err
	}
	pending, err := s.cfg.DB.Enrolments().Pending(ctx, s.cfg.Now())
	if err != nil {
		return nil, err
	}
	links := map[string]time.Time{}
	for _, p := range pending {
		if p.ExpiresAt.After(links[p.UserID]) {
			links[p.UserID] = p.ExpiresAt
		}
	}
	out := make([]UserRow, 0, len(users))
	for _, u := range users {
		out = append(out, UserRow{ID: u.ID, Username: u.Username, Role: authz.Role(u.Role), Disabled: u.Disabled,
			Enrolled: u.TOTPConfirmed, Sessions: counts[u.ID], PendingLink: links[u.ID], CreatedAt: u.CreatedAt})
	}
	return out, nil
}

// User returns one account, or ErrNotFound.
func (s *Service) User(ctx context.Context, id string) (UserRow, error) {
	all, err := s.Users(ctx)
	if err != nil {
		return UserRow{}, err
	}
	for _, u := range all {
		if u.ID == id {
			return u, nil
		}
	}
	return UserRow{}, ErrNotFound
}

// CreateUser adds an account that cannot sign in yet and returns its enrolment link.
// The new user sets their own password and authenticator through the link.
func (s *Service) CreateUser(ctx context.Context, a Actor, username string, role authz.Role) (Link, error) {
	if err := auth.ValidateNewUsername(username); err != nil {
		return Link{}, invalidInput(err.Error())
	}
	if _, err := authz.ParseRole(string(role)); err != nil {
		return Link{}, invalidInput("unknown role")
	}
	hash, err := s.cfg.Hasher.Hash(ctx, randomPassword()) // before the tx: argon2 is slow
	if err != nil {
		return Link{}, err
	}
	now := s.cfg.Now()
	u := store.User{ID: newID(), Username: username, Role: store.Role(role), PwHash: hash, CreatedAt: now}
	var link Link
	err = s.change(ctx, func(tx *store.Tx) (audit.Entry, error) {
		if cerr := tx.Users().Create(ctx, u); cerr != nil {
			return audit.Entry{}, cerr
		}
		l, lerr := s.issueLink(ctx, tx, a, u, store.EnrolPurposeEnrol)
		link = l
		return a.entry("admin.user.create", map[string]any{"target": username, "role": string(role)}), lerr
	})
	if errors.Is(err, store.ErrConflict) {
		return Link{}, ErrUsernameTaken
	}
	return link, err
}

// issueLink supersedes any unused link of u and stores a new one.
func (s *Service) issueLink(ctx context.Context, tx *store.Tx, a Actor, u store.User, p store.EnrolPurpose) (Link, error) {
	now := s.cfg.Now()
	if _, err := tx.Enrolments().InvalidateForUser(ctx, u.ID, now); err != nil {
		return Link{}, err
	}
	raw, hash := auth.NewLinkToken()
	t := store.EnrolmentToken{ID: newID(), UserID: u.ID, TokenHash: hash, Purpose: p, CreatedBy: a.UserID,
		CreatedAt: now, ExpiresAt: now.Add(s.cfg.LinkTTL)}
	if err := tx.Enrolments().Create(ctx, t); err != nil {
		return Link{}, err
	}
	return Link{Token: raw, Username: u.Username, Purpose: p, ExpiresAt: t.ExpiresAt}, nil
}

// SetRole changes a user's role. An admin cannot demote themselves, and the last
// enabled admin cannot be demoted.
func (s *Service) SetRole(ctx context.Context, a Actor, userID string, role authz.Role) error {
	if _, err := authz.ParseRole(string(role)); err != nil {
		return invalidInput("unknown role")
	}
	base := map[string]any{"target_id": userID, "after": string(role)}
	return s.changeOrDeny(ctx, a.entry("admin.user.role", base), func(tx *store.Tx) (audit.Entry, error) {
		u, err := tx.Users().ByID(ctx, userID)
		if err != nil {
			return audit.Entry{}, err
		}
		err = tx.Accounts().SetRoleGuarded(ctx, a.UserID, userID, store.Role(role))
		return a.entry("admin.user.role", with(base, "target", u.Username, "before", string(u.Role))), err
	})
}

// SetDisabled disables (ending every session and unused link) or re-enables a user.
func (s *Service) SetDisabled(ctx context.Context, a Actor, userID string, disabled bool) error {
	action := "admin.user.enable"
	if disabled {
		action = "admin.user.disable"
	}
	base := map[string]any{"target_id": userID}
	return s.changeOrDeny(ctx, a.entry(action, base), func(tx *store.Tx) (audit.Entry, error) {
		u, err := tx.Users().ByID(ctx, userID)
		if err != nil {
			return audit.Entry{}, err
		}
		if err = tx.Accounts().SetDisabledGuarded(ctx, a.UserID, userID, disabled); err == nil && disabled {
			err = endAccess(ctx, tx, userID, s.cfg.Now())
		}
		return a.entry(action, with(base, "target", u.Username)), err
	})
}

// ResetEnrolment removes a user's authenticator, ends their sessions and returns a
// fresh one-time link (also how an expired invitation is re-issued).
func (s *Service) ResetEnrolment(ctx context.Context, a Actor, userID string) (Link, error) {
	base := map[string]any{"target_id": userID}
	var link Link
	err := s.changeOrDeny(ctx, a.entry("admin.user.reset_totp", base), func(tx *store.Tx) (audit.Entry, error) {
		u, err := tx.Users().ByID(ctx, userID)
		if err != nil {
			return audit.Entry{}, err
		}
		if err = tx.Accounts().ClearTOTP(ctx, a.UserID, userID); err != nil {
			return audit.Entry{}, err
		}
		if _, err = tx.Sessions().DeleteForUser(ctx, userID); err != nil {
			return audit.Entry{}, err
		}
		link, err = s.issueLink(ctx, tx, a, u, store.EnrolPurposeReset)
		return a.entry("admin.user.reset_totp", with(base, "target", u.Username)), err
	})
	return link, err
}

// endAccess deletes a user's sessions and unused links inside tx.
func endAccess(ctx context.Context, tx *store.Tx, userID string, now time.Time) error {
	if _, err := tx.Sessions().DeleteForUser(ctx, userID); err != nil {
		return fmt.Errorf("end sessions: %w", err)
	}
	if _, err := tx.Enrolments().InvalidateForUser(ctx, userID, now); err != nil {
		return fmt.Errorf("invalidate links: %w", err)
	}
	return nil
}

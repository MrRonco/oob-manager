package admin

import (
	"context"
	"fmt"

	"oob-manager/internal/audit"
	"oob-manager/internal/store"
)

// RecoverAdmin is the CLI break-glass path (settings_design.md §2, plan 06 drill 8) for
// an install where no admin can sign in: it re-enables username, makes it an admin, clears
// its per-account login lockout and ends its sessions, in one transaction with the
// admin.recover audit row. It deliberately skips the last-admin and self-change guards
// (the shell is trusted) and does not touch the authenticator: if that is lost too,
// follow with reset-totp. Unknown usernames are ErrNotFound. osUser (the shell account
// that ran the command, "" if unknown) goes into the audit params.
func (s *Service) RecoverAdmin(ctx context.Context, a Actor, username, osUser string) error {
	base := map[string]any{"target": username}
	if osUser != "" {
		base["os_user"] = osUser
	}
	return s.changeOrDeny(ctx, a.entry("admin.recover", base), func(tx *store.Tx) (audit.Entry, error) {
		u, err := tx.Users().ByUsername(ctx, username)
		if err != nil {
			return a.entry("admin.recover", base), err
		}
		if err = tx.Users().SetDisabled(ctx, u.ID, false); err != nil {
			return a.entry("admin.recover", base), fmt.Errorf("enable: %w", err)
		}
		if err = tx.Users().SetRole(ctx, u.ID, store.RoleAdmin); err != nil {
			return a.entry("admin.recover", base), fmt.Errorf("set role: %w", err)
		}
		if err = tx.Lockouts().Reset(ctx, "acct:"+username); err != nil {
			return a.entry("admin.recover", base), fmt.Errorf("clear lockout: %w", err)
		}
		ended, err := tx.Sessions().DeleteForUser(ctx, u.ID)
		if err != nil {
			return a.entry("admin.recover", base), fmt.Errorf("end sessions: %w", err)
		}
		return a.entry("admin.recover", with(base, "target_id", u.ID, "before_role", string(u.Role),
			"was_disabled", u.Disabled, "sessions_ended", ended)), nil
	})
}

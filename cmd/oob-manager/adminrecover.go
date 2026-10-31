package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"oob-manager/internal/admin"
	"oob-manager/internal/auth"
)

// adminRecoverCmd is the break-glass path when no admin can sign in (a disabled or
// demoted last admin, or an account locked out by failed passwords): it re-enables the
// account, makes it an admin, clears its per-account login lockout and ends its sessions,
// audited as admin.recover by "cli" with the shell user (settings_design.md §2; recovery
// runbook drill 8). It shows the account's current state and needs -yes or the username
// typed back. The shell is trusted, as for bootstrap-admin and reset-totp; there is no
// web route. It does not reset a password, an authenticator or an IP lockout.
func adminRecoverCmd(e env, args []string) error {
	fs, cfgPath := newFlagSet("admin-recover", e.errOut)
	user := fs.String("username", "", "account to restore as an enabled admin (required)")
	yes := fs.Bool("yes", false, "do not ask for the username to be typed back")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if err = wantPositional("admin-recover", pos, 0); err != nil {
		return err
	}
	if *user == "" {
		return errors.New("admin-recover: -username is required")
	}
	if !auth.ValidUsername(*user) {
		return fmt.Errorf("admin-recover: %q is not a valid username", *user)
	}
	c, err := openMutatingCLICore(e.ctx, *cfgPath, e)
	if err != nil {
		return err
	}
	defer func() { _ = c.close() }()
	u, err := c.db.Users().ByUsername(e.ctx, *user)
	if err != nil {
		return fmt.Errorf("admin-recover: no account %q", *user)
	}
	state := "enabled"
	if u.Disabled {
		state = "disabled"
	}
	_, _ = fmt.Fprintf(e.out, "%q currently: role %s, %s.\n", *user, u.Role, state)
	if !*yes {
		_, _ = fmt.Fprintf(e.out, "Type the username to make it an enabled admin, clear its lockout and end its sessions: ")
		line, rerr := e.in.ReadString('\n')
		if strings.TrimSpace(line) != *user {
			if rerr != nil {
				return errors.New("admin-recover: not confirmed (input closed); nothing changed (use -yes to skip the prompt)")
			}
			return errors.New("admin-recover: not confirmed; nothing changed")
		}
	}
	if err := c.admin.RecoverAdmin(e.ctx, admin.Actor{Username: "cli", Method: "system"}, *user, shellUser()); err != nil {
		return fmt.Errorf("admin-recover: %w", err)
	}
	_, _ = fmt.Fprintf(e.out, "%q is an enabled admin again; its login lockout is cleared and its sessions "+
		"were ended. If its password or authenticator is lost or may be compromised, run reset-totp --user %s "+
		"and set a new password at the next sign-in.\n", *user, *user)
	return nil
}

// shellUser names who ran the command for the audit row: $SUDO_USER when set, then the uid.
func shellUser() string {
	uid := "uid " + strconv.Itoa(os.Getuid())
	if s := os.Getenv("SUDO_USER"); s != "" && auth.ValidUsername(s) {
		return s + " (" + uid + ")"
	}
	return uid
}

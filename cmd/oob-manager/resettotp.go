package main

import (
	"errors"
	"fmt"
)

// resetTOTPCmd gives a user a new TOTP secret and ends all of that user's sessions.
// It exists only on the CLI (shell access is already trusted); there is no web route.
// The secret is printed once, and only to a terminal, after the reset is audited.
func resetTOTPCmd(e env, args []string) error {
	fs, cfgPath := newFlagSet("reset-totp", e.errOut)
	user := fs.String("user", "", "account whose TOTP is reset (required)")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if err = wantPositional("reset-totp", pos, 0); err != nil {
		return err
	}
	if *user == "" {
		return errors.New("reset-totp: --user is required")
	}
	if !e.stdoutTTY() {
		return errors.New("reset-totp: the new secret is only shown on a terminal (docker exec -it)")
	}
	c, err := openMutatingCLICore(e.ctx, *cfgPath, e)
	if err != nil {
		return err
	}
	defer func() { _ = c.close() }()
	enr, err := c.authn.ResetTOTP(e.ctx, *user)
	if err != nil {
		return fmt.Errorf("reset-totp: %w", err)
	}
	if err := c.record(e.ctx, "cli", "admin.totp_reset", map[string]any{"username": *user}); err != nil {
		return errors.New("reset-totp: the TOTP was reset but the audit write failed, so the secret is " +
			"not shown; run reset-totp again")
	}
	_, _ = fmt.Fprintf(e.out, "TOTP for %q reset; all of its sessions were ended. Add it to the "+
		"authenticator app now; this is shown ONCE.\n  Secret: %s\n  URI:    %s\n"+
		"Then confirm with the enrolment page (/enroll) or `oob-manager confirm-totp -username %s`.\n",
		*user, enr.Secret, enr.URL, *user)
	return nil
}

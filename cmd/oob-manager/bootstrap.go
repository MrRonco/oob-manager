package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"oob-manager/internal/auth"
	"oob-manager/internal/secrets"
)

// confirmAttempts is how many TOTP codes the CLI accepts before giving up (lockout
// still applies on top).
const confirmAttempts = 3

// cliIP is the lockout key "source" for CLI enrollment.
const cliIP = "local-cli"

// bootstrapCmd creates the first admin. The password is read from the terminal with
// echo off; the TOTP secret and provisioning URI are printed exactly once.
func bootstrapCmd(e env, args []string) error {
	cfg, user, notes, err := parseFlags("bootstrap-admin", args, e, true, loadConfig)
	printStartNotes(e.errOut, notes)
	if err != nil {
		return err
	}
	c, err := openCore(e.ctx, cfg, newLogger(e.errOut, slog.LevelWarn))
	if err != nil {
		return err
	}
	c.startCLIShipping(e)
	defer func() { _ = c.close() }()
	pw, err := newPassword(e)
	if err != nil {
		return err
	}
	enr, err := c.authn.BootstrapAdmin(e.ctx, user, pw)
	if err != nil {
		return err
	}
	_ = c.record(e.ctx, "cli", "admin.bootstrap", map[string]any{"username": user})
	_, _ = fmt.Fprintf(e.out, "Admin %q created. Add it to your authenticator app now; this is shown ONCE.\n"+
		"  Secret: %s\n  URI:    %s\n", user, enr.Secret, enr.URL)
	return confirmLoop(e, c, user, pw)
}

// confirmCmd completes a pending enrollment (if bootstrap-admin was interrupted).
func confirmCmd(e env, args []string) error {
	cfg, user, notes, err := parseFlags("confirm-totp", args, e, true, loadConfig)
	printStartNotes(e.errOut, notes)
	if err != nil {
		return err
	}
	c, err := openCore(e.ctx, cfg, newLogger(e.errOut, slog.LevelWarn))
	if err != nil {
		return err
	}
	c.startCLIShipping(e)
	defer func() { _ = c.close() }()
	pw, err := readSecret(e, "Password: ")
	if err != nil {
		return err
	}
	return confirmLoop(e, c, user, pw)
}

func confirmLoop(e env, c *core, user, pw string) error {
	for i := 0; i < confirmAttempts; i++ {
		_, _ = fmt.Fprint(e.errOut, "6-digit code from the authenticator: ")
		code, err := readLine(e.in)
		if err != nil {
			break
		}
		err = c.authn.ConfirmTOTP(e.ctx, user, pw, code, cliIP)
		if err == nil {
			_ = c.record(e.ctx, "cli", "admin.totp_confirmed", map[string]any{"username": user})
			_, _ = fmt.Fprintln(e.out, "TOTP confirmed. You can now log in.")
			return nil
		}
		if errors.Is(err, auth.ErrLockedOut) {
			return err
		}
		_, _ = fmt.Fprintln(e.errOut, "That code was not accepted.")
	}
	return fmt.Errorf("TOTP not confirmed; the account cannot log in until you run "+
		"`oob-manager confirm-totp -username %s`", user)
}

// newPassword prompts twice and checks the policy before any hashing happens.
func newPassword(e env) (string, error) {
	pw, err := readSecret(e, "New password: ")
	if err != nil {
		return "", err
	}
	if err = auth.ValidatePassword(pw); err != nil {
		return "", err
	}
	again, err := readSecret(e, "Repeat password: ")
	if err != nil {
		return "", err
	}
	if pw != again {
		return "", errors.New("passwords do not match")
	}
	return pw, nil
}

// readSecret prompts on stderr and reads one line with terminal echo off. It refuses
// to run without a terminal so a password is never echoed or read from a pipe by mistake.
func readSecret(e env, prompt string) (string, error) {
	_, _ = fmt.Fprint(e.errOut, prompt)
	restore, err := e.noEcho()
	if err != nil {
		return "", fmt.Errorf("an interactive terminal is required (docker exec -it): %w", err)
	}
	line, err := readLine(e.in)
	restore()
	_, _ = fmt.Fprintln(e.errOut)
	return line, err
}

func readLine(r interface{ ReadString(byte) (string, error) }) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", errors.New("input closed")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// genAppKeysCmd prints a fresh app-keys document to stdout (never to disk).
func genAppKeysCmd(e env) error {
	doc, err := secrets.GenerateAppKeys()
	if err != nil {
		return err
	}
	if _, err := e.out.Write(doc); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(e.errOut, "pipe this into: age -r <recipient> -o app-keys.age")
	return nil
}

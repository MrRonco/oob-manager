package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/auth"
	"oob-manager/internal/store"
)

// tokenCmd dispatches `token create|list|revoke`.
func tokenCmd(e env, args []string) error {
	if len(args) == 0 {
		return errors.New("token: expected create, list or revoke")
	}
	switch args[0] {
	case "create":
		return tokenCreateCmd(e, args[1:])
	case "list":
		return tokenListCmd(e, args[1:])
	case "revoke":
		return tokenRevokeCmd(e, args[1:])
	default:
		return fmt.Errorf("token: unknown subcommand %q (want create, list or revoke)", args[0])
	}
}

type tokenCreateArgs struct {
	configPath string
	name       string
	owner      string
	ttl        time.Duration
}

func parseTokenCreate(args []string, e env) (tokenCreateArgs, error) {
	fs, cfgPath := newFlagSet("token create", e.errOut)
	name := fs.String("name", "", "label for the token, e.g. dashboard (required)")
	expires := fs.String("expires", "never", "lifetime: <N>d, a Go duration such as 720h, or never")
	owner := fs.String("owner", "", "admin the token is attributed to (default: the only admin)")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return tokenCreateArgs{}, err
	}
	if err = wantPositional("token create", pos, 0); err != nil {
		return tokenCreateArgs{}, err
	}
	if *name == "" {
		return tokenCreateArgs{}, errors.New("token create: --name is required")
	}
	ttl, err := parseLifetime(*expires)
	if err == nil {
		err = auth.ValidateTokenLifetime(ttl)
	}
	if err != nil {
		return tokenCreateArgs{}, err
	}
	return tokenCreateArgs{configPath: *cfgPath, name: *name, owner: *owner, ttl: ttl}, nil
}

// parseLifetime accepts "never", "<N>d" (days) or a Go duration.
func parseLifetime(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "never" {
		return 0, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("--expires %q: want a positive number of days", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("--expires %q: want <N>d, a duration such as 720h, or never", s)
	}
	return d, nil
}

// tokenCreateCmd mints a read-only API token. The token goes to stdout exactly once,
// alone on its line, so it can be piped; everything else goes to stderr.
func tokenCreateCmd(e env, args []string) error {
	a, err := parseTokenCreate(args, e)
	if err != nil {
		return err
	}
	c, err := openMutatingCLICore(e.ctx, a.configPath, e)
	if err != nil {
		return err
	}
	defer func() { _ = c.close() }()
	owner, err := tokenOwner(e.ctx, c.db.Users(), a.owner)
	if err != nil {
		return err
	}
	// One code path with the settings UI: the token and its audit row commit together,
	// so a token can never exist unaudited.
	raw, tok, err := c.admin.CreateToken(e.ctx, cliActor, owner.ID, a.name, a.ttl)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(e.errOut, "Token %s (%q, read-only, expires %s) created. It is shown ONCE:\n",
		tok.ID, tok.Name, fmtExpiry(tok.ExpiresAt))
	_, _ = fmt.Fprintln(e.out, raw)
	return nil
}

// tokenOwner resolves --owner, or the only admin when it is empty.
func tokenOwner(ctx context.Context, users store.UserRepository, username string) (store.User, error) {
	if username != "" {
		u, err := users.ByUsername(ctx, username)
		if err != nil {
			return store.User{}, fmt.Errorf("token create: --owner %q: no such user", username)
		}
		return u, nil
	}
	all, err := users.List(ctx)
	if err != nil {
		return store.User{}, err
	}
	var admins []store.User
	for _, u := range all {
		if u.Role == store.RoleAdmin && !u.Disabled {
			admins = append(admins, u)
		}
	}
	if len(admins) != 1 {
		return store.User{}, fmt.Errorf("token create: %d active admins; name one with --owner", len(admins))
	}
	return admins[0], nil
}

// openCLICore loads the config (path, or the defaults when empty) and opens the core with a quiet logger.
func openCLICore(ctx context.Context, path string, e env) (*core, error) {
	cfg, err := loadCLIConfig(e, path) // only problems are printed, not the deprecation warnings
	if err != nil {
		return nil, err
	}
	return openCore(ctx, cfg, newLogger(e.errOut, slog.LevelWarn))
}

// openMutatingCLICore is openCLICore for commands that write audit rows: it also ships
// them to the log server (startCLIShipping), flushed by close().
func openMutatingCLICore(ctx context.Context, path string, e env) (*core, error) {
	c, err := openCLICore(ctx, path, e)
	if err == nil {
		c.startCLIShipping(e)
	}
	return c, err
}

func fmtExpiry(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return fmtCLITime(t)
}

func fmtCLITime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

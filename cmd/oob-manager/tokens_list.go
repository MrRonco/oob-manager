package main

import (
	"errors"
	"fmt"
	"text/tabwriter"
	"time"

	"oob-manager/internal/auth"
)

// tokenListCmd prints every token's metadata. The token value is never stored, so it
// cannot be listed.
func tokenListCmd(e env, args []string) error {
	fs, cfgPath := newFlagSet("token list", e.errOut)
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if err = wantPositional("token list", pos, 0); err != nil {
		return err
	}
	c, err := openCLICore(e.ctx, *cfgPath, e)
	if err != nil {
		return err
	}
	defer func() { _ = c.close() }()
	list, err := c.tokens.List(e.ctx)
	if err != nil {
		return err
	}
	return writeTokenTable(e, list, time.Now())
}

func writeTokenTable(e env, list []auth.APIToken, now time.Time) error {
	if len(list) == 0 {
		_, _ = fmt.Fprintln(e.errOut, "No API tokens.")
		return nil
	}
	tw := tabwriter.NewWriter(e.out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tNAME\tCREATED\tLAST USED\tEXPIRES\tSTATUS")
	for _, t := range list {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", t.ID, t.Name, fmtCLITime(t.CreatedAt),
			fmtCLITime(t.LastUsedAt), fmtExpiry(t.ExpiresAt), t.StatusAt(now))
	}
	return tw.Flush()
}

// tokenRevokeCmd revokes one token by ID and audits it.
func tokenRevokeCmd(e env, args []string) error {
	fs, cfgPath := newFlagSet("token revoke", e.errOut)
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if err = wantPositional("token revoke", pos, 1); err != nil {
		return errors.New("usage: oob-manager token revoke <id>")
	}
	c, err := openMutatingCLICore(e.ctx, *cfgPath, e)
	if err != nil {
		return err
	}
	defer func() { _ = c.close() }()
	tok, err := findActiveToken(e, c, pos[0])
	if err != nil {
		return err
	}
	if err := c.admin.RevokeToken(e.ctx, cliActor, tok.ID); err != nil {
		return fmt.Errorf("token revoke: %w", err)
	}
	_, _ = fmt.Fprintf(e.out, "Token %s (%q) revoked.\n", tok.ID, tok.Name)
	return nil
}

func findActiveToken(e env, c *core, id string) (auth.APIToken, error) {
	list, err := c.tokens.List(e.ctx)
	if err != nil {
		return auth.APIToken{}, err
	}
	for _, t := range list {
		if t.ID == id && t.RevokedAt.IsZero() {
			return t, nil
		}
	}
	return auth.APIToken{}, errors.New("token revoke: no unrevoked token with that ID (see `oob-manager token list`)")
}

package main

import (
	"context"
	"time"

	"oob-manager/internal/bmcreset"
)

// lockoutRetention is the longest auth.LockoutPolicy.ForgetAfter (tech_doc §10).
const lockoutRetention = 24 * time.Hour

// linkRetention keeps expired enrolment links a week, so the users page can still tell
// an admin that a link expired unused.
const linkRetention = 7 * 24 * time.Hour

// janitor deletes expired sessions, stale login-failure rows, old enrolment links, BMC restart rows
// older than bmcreset.Retention (400 days) and, through extra, firmware version changes
// older than fwinventory.ChangeRetention (2 years), at start and then
// every interval, until ctx ends. The sensor history runs its own janitor (history.Service.Run).
func janitor(ctx context.Context, c *core, every time.Duration, extra ...func(context.Context)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		sweep(ctx, c, time.Now(), extra...)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// sweep runs one pass; extra are the services' own prunes (the firmware view's changes).
func sweep(ctx context.Context, c *core, now time.Time, extra ...func(context.Context)) {
	p := c.authPolicy()
	if _, err := c.db.Sessions().DeleteExpired(ctx, now.Add(-p.SessionIdle),
		now.Add(-p.SessionMax)); err != nil && ctx.Err() == nil {
		c.log.Warn("janitor: delete expired sessions failed", "error", err)
	}
	if _, err := c.db.Lockouts().Prune(ctx, now.Add(-lockoutRetention)); err != nil && ctx.Err() == nil {
		c.log.Warn("janitor: prune lockouts failed", "error", err)
	}
	if _, err := c.db.Enrolments().Prune(ctx, now.Add(-linkRetention)); err != nil && ctx.Err() == nil {
		c.log.Warn("janitor: prune enrolment links failed", "error", err)
	}
	if _, err := c.db.BMCResets().Prune(ctx, now.Add(-bmcreset.Retention)); err != nil && ctx.Err() == nil {
		c.log.Warn("janitor: prune BMC restart rows failed", "error", err)
	}
	for _, fn := range extra {
		fn(ctx)
	}
}

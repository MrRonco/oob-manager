package main

import (
	"context"
	"log/slog"
	"sync/atomic"

	"oob-manager/internal/api"
	"oob-manager/internal/fleet"
	"oob-manager/internal/maint"
	"oob-manager/internal/notify"
)

// lateEmit forwards maintenance start/end messages to the notifications service once it
// exists (maint is built first: notifications take it as their Suppressor).
type lateEmit struct {
	p atomic.Pointer[notify.Service]
}

func (l *lateEmit) emit(e notify.Event) {
	if s := l.p.Load(); s != nil {
		s.Emit(e)
	}
}

// buildMaint builds maintenance mode, notes and acknowledgements over the database
// (tech_doc §28). Server names for its notifications come from the live fleet.
func buildMaint(ctx context.Context, c *core, fl fleet.Reader, out *lateEmit, log *slog.Logger) (*maint.Service, error) {
	name := func(id string) string {
		if s, ok := fl.Server(id); ok {
			return s.Name
		}
		return id
	}
	return maint.New(ctx, maint.Config{DB: c.db, Audit: c.audit, Emit: out.emit, ServerName: name, Logger: log})
}

// apiMaint keeps a nil *maint.Service a nil interface (the API then reports none).
func apiMaint(m *maint.Service) api.MaintenanceReader {
	if m == nil {
		return nil
	}
	return m
}

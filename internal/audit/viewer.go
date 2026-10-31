package audit

import (
	"context"

	"oob-manager/internal/store"
)

// Viewer is the read side of the audit chain for the settings audit page: filtered
// keyset-paginated search and a full chain verification.
type Viewer struct {
	repo   store.AuditRepository
	search store.AuditSearcher
}

// NewViewer returns a Viewer over the audit table.
func NewViewer(repo store.AuditRepository, search store.AuditSearcher) Viewer {
	return Viewer{repo: repo, search: search}
}

// Search returns rows matching f, newest first.
func (v Viewer) Search(ctx context.Context, f store.AuditFilter) ([]store.AuditRecord, error) {
	return v.search.Search(ctx, f)
}

// Actions lists the distinct recorded actions.
func (v Viewer) Actions(ctx context.Context) ([]string, error) { return v.search.Actions(ctx) }

// Verify walks the whole chain (see Verify).
func (v Viewer) Verify(ctx context.Context) (VerifyResult, error) {
	return Verify(ctx, v.repo, DefaultVerifyPage)
}

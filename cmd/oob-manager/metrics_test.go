package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/config"
	"oob-manager/internal/maint"
	"oob-manager/internal/metrics"
	"oob-manager/internal/store"
)

func TestBuildMetricsDisabled(t *testing.T) {
	h, err := buildMetrics(config.Config{}, &core{}, emptyFleet{}, consoleDeps{})
	if err != nil || h != nil {
		t.Fatalf("disabled metrics built a handler: %v %v", h, err)
	}
}

func TestBuildMetricsEnabled(t *testing.T) {
	c := &core{logins: &metrics.LoginCounter{}, chainBroken: true}
	c.logins.Failure(metrics.StageTOTP)
	h, err := buildMetrics(config.Config{Metrics: config.MetricsConfig{Enabled: true}}, c, emptyFleet{}, consoleDeps{})
	if err != nil || h == nil {
		t.Fatalf("enabled metrics: %v", err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil))
	for _, want := range []string{"oob_audit_chain_ok 0", `oob_login_failures_total{stage="totp"} 1`,
		`oob_build_info{version="` + version + `"`, `oob_console_sessions_active{type="vnc"} 0`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("missing %q in:\n%s", want, w.Body.String())
		}
	}
}

// TestMetricsReadMaintenance: /metrics reports the maintenance service's real window
// (active, end time) and its acknowledgements; a nil service reports none.
func TestMetricsReadMaintenance(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	m, err := maint.New(ctx, maint.Config{DB: db, Audit: audit.NewLogger(db.Audit(), nil, time.Now, nil)})
	if err != nil {
		t.Fatal(err)
	}
	a := admin.Actor{UserID: "u1", Username: "op", Role: authz.RoleOperator, Method: "local"}
	w, err := m.Start(ctx, a, "srv-a", maint.StartRequest{Reason: "PSU swap", Duration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ref := maint.EventRef{ServerID: "srv-a", Log: maint.LogSEL, EntryID: "7", Created: time.UnixMilli(1000).UTC()}
	if _, err := m.Ack(ctx, a, "srv-a", []maint.EventRef{ref}, ""); err != nil {
		t.Fatal(err)
	}
	state, acked := maintMetrics(m)
	if st := state("srv-a"); !st.Active || !st.Until.Equal(w.EndsAt) {
		t.Fatalf("srv-a %+v", st)
	}
	if st := state("srv-b"); st.Active || !st.Until.IsZero() {
		t.Fatalf("srv-b %+v", st)
	}
	if !acked("srv-a", "sel", "7", ref.Created) || acked("srv-a", "sel", "8", ref.Created) {
		t.Fatal("acks")
	}
	if s, a := maintMetrics(nil); s != nil || a != nil {
		t.Fatal("nil service must leave the hooks unset")
	}
}

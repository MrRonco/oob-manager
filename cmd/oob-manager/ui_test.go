package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/config"
	"oob-manager/internal/fleet"
	"oob-manager/internal/store"
	"oob-manager/internal/store/authrepo"
)

type emptyFleet struct{}

func (emptyFleet) Servers() []fleet.ServerState            { return nil }
func (emptyFleet) Server(string) (fleet.ServerState, bool) { return fleet.ServerState{}, false }
func (emptyFleet) Polled() bool                            { return false }

func testUIDeps(t *testing.T) UIDeps {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, t.TempDir()+"/ui.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	hasher, err := auth.NewPasswordHasher(auth.DefaultArgon2Params(), 1)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := auth.NewAESGCMSealer(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	repos := authrepo.New(db)
	a, err := auth.New(auth.Config{Users: repos.Users, Sessions: repos.Sessions, Lockouts: repos.Lockouts,
		Hasher: hasher, Sealer: sealer, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	return UIDeps{Fleet: emptyFleet{}, Auth: a, Audit: audit.NewLogger(db.Audit(), nil, nil, log),
		CSRFKey: bytes.Repeat([]byte{9}, 32), Logger: log}
}

func TestNewUIHandlerServesLogin(t *testing.T) {
	h, err := newUIHandler(testUIDeps(t))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="password"`) {
		t.Fatalf("login page: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("overview without session: %d %v", rec.Code, rec.Header())
	}
}

func TestNewUIHandlerRequiresDerivedCSRFKey(t *testing.T) {
	d := testUIDeps(t)
	d.CSRFKey = nil
	if _, err := newUIHandler(d); err == nil {
		t.Fatal("missing CSRF key accepted (a random per-process key must not be the default here)")
	}
	d = testUIDeps(t)
	d.Auth = nil
	if _, err := newUIHandler(d); err == nil {
		t.Fatal("nil Auth accepted")
	}
}

func TestLifecycleFromConfig(t *testing.T) {
	cfg := config.Config{Servers: []config.Server{
		{ID: "a", BMC: config.BMCConfig{Kind: config.KindIDRAC8}},
		{ID: "b", BMC: config.BMCConfig{Kind: config.KindIDRAC9}},
		{ID: "c", BMC: config.BMCConfig{Kind: config.KindRedfish}},
	}}
	has := lifecycleFromConfig(cfg)
	if !has("a") || !has("b") || has("c") || has("zz") {
		t.Fatal("lifecycle mapping wrong")
	}
}

func TestUIStaleAfter(t *testing.T) {
	if got := uiStaleAfter(config.Config{}); got != 0 {
		t.Fatalf("zero interval: %v", got)
	}
	cfg := config.Config{Poll: config.PollConfig{Interval: 45e9}}
	if got := uiStaleAfter(cfg); got != 135e9 {
		t.Fatalf("got %v", got)
	}
}

func TestNewUIHandlerShowsInstanceName(t *testing.T) {
	d := testUIDeps(t)
	d.Config.UI.InstanceName = "Lab OOB"
	h, err := newUIHandler(d)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login", nil))
	if !strings.Contains(rec.Body.String(), "Lab OOB") {
		t.Fatalf("instance name missing from the sign-in page:\n%s", rec.Body.String())
	}
}

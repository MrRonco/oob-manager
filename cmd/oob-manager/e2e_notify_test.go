//go:build e2e

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"oob-manager/internal/notify"
)

// e2eHookSecret signs the file-managed webhook (test-only value in the temp age file).
const e2eHookSecret = "e2e-hook-hmac-not-a-secret" //nolint:gosec // G101: test fixture

// hookRecv is a local webhook receiver (plain HTTP on 127.0.0.1, reached through
// notifications.allowed_networks and allow_plaintext). It checks every signature.
type hookRecv struct {
	srv     *httptest.Server
	mu      sync.Mutex
	got     []notify.WebhookPayload
	badSigs int
}

func newHookRecv(t *testing.T) *hookRecv {
	t.Helper()
	h := &hookRecv{}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var p notify.WebhookPayload
		_ = json.Unmarshal(body, &p)
		ok := r.Header.Get(notify.HeaderSignature) == notify.Sign([]byte(e2eHookSecret), r.Header.Get(notify.HeaderTimestamp), body)
		h.mu.Lock()
		h.got = append(h.got, p)
		if !ok && r.URL.Path == "/file-hook" {
			h.badSigs++
		}
		h.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hookRecv) payloads() []notify.WebhookPayload {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]notify.WebhookPayload(nil), h.got...)
}

func (h *hookRecv) has(class notify.Class, sub string) bool {
	for _, p := range h.payloads() {
		if p.Class == class && strings.Contains(p.Title+" "+p.Message, sub) {
			return true
		}
	}
	return false
}

// notifyYAML is the stack's notifications section: one file-managed, signed webhook.
func (s *stack) notifyYAML() string {
	return `notifications:
  allowed_networks: [127.0.0.0/8]
  targets:
    - id: e2e-hook
      name: E2E hook
      kind: webhook
      url: ` + s.hooks.srv.URL + `/file-hook
      allow_plaintext: true
      secret_ref: notify-hook
      min_severity: info
`
}

// checkNotifyEvents runs in the main stack after the power and console checks: their
// audit records must have reached the file-managed webhook, signed, and the target is
// listed with a lock badge. It makes no change (the main flow is near the change limit).
func checkNotifyEvents(t *testing.T, b browser, s *stack) {
	waitFor(t, "power and console notifications", func() bool {
		return s.hooks.has(notify.ClassPower, "power force off requested") && s.hooks.has(notify.ClassConsole, "console session started")
	})
	expectPage(t, b.get("/settings/notifications"), "E2E hook", "Managed by config.yaml", "Secret from the credential file", "Working")
	checkHookSignatures(t, s)
}

// checkNotifySettings runs a second stack: Send test on the file target, a browser-made
// target added, tested and deleted, maintenance mode, notes and acknowledgements
// (checkMaintenance), all audited, and the
// webhook secret never in the log or a page.
func checkNotifySettings(t *testing.T) {
	s := startStack(t, "127.0.0.1:0")
	b := browser{t: t, base: s.base, c: s.client(t)}
	login(t, b, s)
	expectRedirect(t, b.submit("/settings/notifications", "/settings/notifications/e2e-hook/test", url.Values{}),
		"/settings/notifications?done=notify-test")
	waitFor(t, "test notification", func() bool { return s.hooks.has(notify.ClassTest, "Test from oob-manager") })

	form := url.Values{"kind": {"webhook"}, "id": {"ui-hook"}, "name": {"UI hook"}, "url": {s.hooks.srv.URL + "/ui-hook"},
		"allow_plaintext": {"on"}, "enabled": {"on"}, "min_severity": {"critical"}, "classes": {"health"}}
	expectRedirect(t, b.submit("/settings/notifications/new?kind=webhook", "/settings/notifications", form),
		"/settings/notifications?done=notify-created")
	expectRedirect(t, b.submit("/settings/notifications", "/settings/notifications/ui-hook/test", url.Values{}),
		"/settings/notifications?done=notify-test")
	list := b.get("/settings/notifications")
	expectPage(t, list, "UI hook", "Working")
	expectPage(t, b.get("/settings/notifications/ui-hook/delete"), "Delete notification target UI hook?")
	expectRedirect(t, b.submit("/settings/notifications/ui-hook/delete", "/settings/notifications/ui-hook/delete",
		url.Values{"confirm": {"yes"}}), "/settings/notifications?done=notify-deleted")

	checkMaintenance(t, b, s)
	checkHookSignatures(t, s)
	if strings.Contains(list.body, e2eHookSecret) {
		t.Fatal("the webhook secret reached a page")
	}
	if code := s.stop(); code != 0 {
		t.Fatalf("serve exit %d", code)
	}
	if strings.Contains(s.errOut.String(), e2eHookSecret) {
		t.Fatal("the webhook secret reached the application log")
	}
	assertAudited(t, s.dbPath, "admin.notify.create", "admin.notify.test", "admin.notify.delete",
		"server.maintenance.start", "server.maintenance.end", "server.note.add", "server.note.pin", "server.event.ack")
}

func checkHookSignatures(t *testing.T, s *stack) {
	t.Helper()
	s.hooks.mu.Lock()
	bad := s.hooks.badSigs
	s.hooks.mu.Unlock()
	if bad != 0 {
		t.Fatalf("%d file-hook deliveries with a bad signature", bad)
	}
}

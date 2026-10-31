package notify

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc/dellredfish"
	"oob-manager/internal/bmc/redfish"
	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/fleet"
)

// TestRedfishStateChangesReachReceivers runs the real poller and Redfish driver against
// a mock iDRAC9, changes the mock's state, and checks what a webhook receiver gets:
// health Critical → recovered, BMC down → recovered, each exactly once.
func TestRedfishStateChangesReachReceivers(t *testing.T) {
	mock := redfishmock.New(t, redfishmock.FixtureDir(t, "idrac9-r240"))
	drv, err := dellredfish.New(redfish.Config{Endpoint: mock.URL(), Username: redfishmock.User,
		Password: redfishmock.Password, PinSHA256: mock.PinSHA256(), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	fl, err := fleet.New(fleet.Config{Targets: []fleet.Target{{ID: "r240", Name: "Edge node", Driver: drv}},
		// A loaded runner (-race, many packages) can take well over 100 ms for one cycle, which
		// made the server look unreachable before the health change. The mock's "down" answers
		// 503 at once, so generous limits do not slow the reachability steps.
		Logger: quiet(), Interval: 50 * time.Millisecond, CycleTimeout: 2 * time.Second,
		StaleAfter: 4 * time.Second, BreakerThreshold: 1000, EventsEvery: time.Hour, InventoryEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	fleetDone := make(chan struct{})
	go func() { fl.Run(ctx); close(fleetDone) }()
	t.Cleanup(func() { cancel(); <-fleetDone })

	r := newReceiver(t, true)
	env := newSvcEnv(t, r, func(c *Config) {
		c.Fleet, c.WatchEvery, c.Debounce, c.Now = fl, 20*time.Millisecond, 150*time.Millisecond, time.Now
		c.Audit = nil
		c.DB, c.Sealer = nil, nil
		hook := target(KindWebhook, r.srv.URL+"/hook")
		c.File = []FileTarget{{Target: hook}}
	})
	env.run(t)
	waitFor(t, "first poll", fl.Polled)

	const sys = "/redfish/v1/Systems/System.Embedded.1"
	doc, ok := mock.Fixture(sys)
	if !ok {
		t.Fatal("system fixture")
	}
	mock.SetOverlay(sys, strings.ReplaceAll(string(doc), `"HealthRollup": "OK"`, `"HealthRollup": "Critical"`))
	got := expectEvents(t, r, 1)
	mock.ClearOverlay(sys)
	got = append(got, expectEvents(t, r, 2)[1:]...)
	mock.SetDown(true)
	got = append(got, expectEvents(t, r, 3)[2:]...)
	mock.SetDown(false)
	got = append(got, expectEvents(t, r, 4)[3:]...)

	want := []string{"health critical false", "health critical true", "reachability critical false", "reachability critical true"}
	for i, p := range got {
		if s := string(p.Class) + " " + p.Severity + " " + map[bool]string{true: "true", false: "false"}[p.Recovery]; s != want[i] {
			t.Errorf("event %d = %q, want %q (%s)", i, s, want[i], p.Title)
		}
		if p.Server == nil || p.Server.ID != "r240" || p.Server.Name != "Edge node" {
			t.Errorf("event %d server %+v", i, p.Server)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if n := r.count(); n != 4 {
		t.Fatalf("duplicates: %d deliveries", n)
	}
}

// expectEvents waits until r has n requests and decodes them.
func expectEvents(t *testing.T, r *receiver, n int) []WebhookPayload {
	t.Helper()
	waitFor(t, "webhook deliveries", func() bool { return r.count() >= n })
	var out []WebhookPayload
	for _, c := range r.requests() {
		var p WebhookPayload
		if err := json.Unmarshal(c.Body, &p); err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

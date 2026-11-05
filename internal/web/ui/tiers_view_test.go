package ui

import (
	"net/http"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

func TestServerPageShowsPollDuration(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t)
	h.fleet.servers[0].LastPollDuration = 4210 * time.Millisecond
	result(c.get("/servers/r730xd")).status(t, http.StatusOK).contains(t, "poll 4.2 s")
	result(c.get("/servers/spare")).status(t, http.StatusOK).lacks(t, "poll 4")
}

func TestSectionStalenessOnlyWhenOverdue(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t)
	now := h.clock.Now()
	h.fleet.servers[0].InventoryAsOf = now.Add(-7 * time.Hour)
	result(c.get("/servers/r730xd")).status(t, http.StatusOK).lacks(t, "is overdue")
	h.fleet.servers[0].InventoryOverdue = true
	result(c.get("/servers/r730xd")).status(t, http.StatusOK).
		contains(t, "Inventory last read", "7 h ago", "refresh is overdue")
	result(c.get("/servers/r730xd/inventory")).status(t, http.StatusOK).contains(t, "refresh is overdue")
}

func TestLogsPageOverdueNotice(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t)
	h.fleet.logs["r730xd/sel"] = bmc.NewEventLog("/sel", []bmc.Event{{ID: "1", Message: "x"}}, true)
	result(c.get("/servers/r730xd/events")).status(t, http.StatusOK).lacks(t, "refresh is overdue")
	h.fleet.servers[0].SELAsOf, h.fleet.servers[0].SELOverdue = h.clock.Now().Add(-20*time.Minute), true
	result(c.get("/servers/r730xd/events")).status(t, http.StatusOK).contains(t, "System Event Log last read", "20 min ago", "refresh is overdue")
	h.fleet.servers[0].LifecycleOverdue, h.fleet.servers[0].LifecycleAsOf = true, h.clock.Now().Add(-time.Hour)
	h.fleet.logs["r730xd/lifecycle"] = bmc.NewEventLog("/lc", nil, true)
	result(c.get("/servers/r730xd/events?log=lifecycle")).status(t, http.StatusOK).contains(t, "Lifecycle log last read")
}

func TestPerServerStaleAfter(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t)
	h.fleet.servers[1].StaleAfter = time.Hour // r240 is 10 min old; its own threshold wins
	result(c.get("/servers/r240")).status(t, http.StatusOK).lacks(t, "Data stale.")
}

package ui

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
	"oob-manager/internal/power"
)

// Audit R2-15: every confirm page used the red "destructive" treatment, so the danger
// signal meant nothing. Three tiers now: neutral (reversible, safe), caution (service
// impact, recoverable) and danger (forced or irreversible). Audit R2-11: viewers get
// status, not controls that lead nowhere.

func TestPowerConfirmTiers(t *testing.T) {
	t.Parallel()
	e := newPowerEnv(t, authz.RoleAdmin)
	off := powerServer(e.h.clock.Now().Add(time.Hour), "off", "Off box", nil, allResetTypes)
	off.Snapshot = bmc.NewSnapshot(bmc.SnapshotParams{TakenAt: off.LastSuccess, PowerState: bmc.PowerOff, Health: bmc.HealthOK})
	e.fp.info["off"] = power.Info{Configured: true, Operator: true}
	e.h.fleet.servers = append(e.h.fleet.servers, off)
	// Power on: reversible and safe, so the accent button and an informational panel.
	result(e.c.get("/servers/off/power/on")).status(t, http.StatusOK).
		contains(t, `<section class="panel p-info"`, `<button class="btn" type="submit">Power on Off box</button>`, "b-info").
		lacks(t, "btn-danger", "p-danger", "b-warn")
	// A graceful shutdown has service impact but is recoverable: caution.
	result(e.c.get("/servers/store/power/graceful-shutdown")).status(t, http.StatusOK).
		contains(t, `<section class="panel p-warn"`, `<button class="btn btn-caution" type="submit">`, "Safe action").
		lacks(t, "btn-danger", "p-danger", "b-warn")
	// Forced actions keep the red treatment.
	result(e.c.get("/servers/edge/power/force-off")).status(t, http.StatusOK).
		contains(t, `<section class="panel p-danger"`, `<button class="btn btn-danger" type="submit">`, "Forced action")
}

func TestFanReviewIsNeutral(t *testing.T) {
	t.Parallel()
	_, c, _ := fanSignedIn(t, authz.RoleOperator)
	result(c.do(http.MethodPost, "/servers/r730xd/fan/lease", fanForm(t, c, nil))).status(t, http.StatusOK).
		contains(t, "Reversible", `<section class="panel p-info"`, `<button class="btn" type="submit">Start lease</button>`).
		lacks(t, "btn-danger", "p-danger", "Can be undone")
}

func TestSettingsConfirmTiers(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t)
	c := e.adminClient()
	userPage := victorPage(t, e, c)
	result(c.get(userPage)).status(t, http.StatusOK).
		contains(t, `class="btn btn-caution" href="`+userPage+`/disable"`, `class="btn btn-danger-outline" href="`+userPage+`/reset-totp"`)
	result(c.get(userPage+"/disable")).contains(t, "Reversible", `<section class="panel p-warn"`, "btn-caution").
		lacks(t, "Can be undone", "btn-danger", "p-danger")
	result(c.get(userPage+"/reset-totp")).contains(t, "Cannot be undone", `<section class="panel p-danger"`, `class="btn btn-danger"`)
	result(c.get(userPage+"/sessions/revoke-all")).contains(t, "Reversible", `<section class="panel p-warn"`, "btn-caution")
	// A token revocation cannot be undone.
	c.submit("/settings/tokens", "/settings/tokens", url.Values{"name": {"dashboard"}, "expires": {"90"}})
	result(c.get("/settings/tokens")).contains(t, `class="btn btn-danger-outline btn-small" href="/settings/tokens/`)
}

func TestServerSettingsConfirmTiers(t *testing.T) {
	t.Parallel()
	e := newServersEnv(t, "")
	c := e.adminClient()
	e.fetchAndConfirm(t, c, "edge1", "192.0.2.12").status(t, http.StatusSeeOther)
	page := "/settings/servers/edge1"
	result(c.submit(page, page+"/credentials/readonly", url.Values{"rev": {"1"}, "username": {"u"}, "password": {"p"}}))
	result(c.submit(page, page+"/enable", url.Values{"rev": {"2"}})).status(t, http.StatusSeeOther)
	result(c.get(page)).status(t, http.StatusOK).
		contains(t, `class="btn btn-caution" href="`+page+`/disable"`, `class="btn btn-danger-outline" href="`+page+`/delete"`)
	result(c.get(page+"/disable")).contains(t, "Reversible", `<section class="panel p-warn"`, "btn-caution").lacks(t, "btn-danger", "p-danger")
	result(c.get(page+"/delete")).contains(t, "Cannot be undone", `<section class="panel p-danger"`, `class="btn btn-danger"`)
}

// Viewers get status, not controls (audit R2-11): no action buttons that lead to a page
// where everything is disabled, one line that says which role acts. An operator, one
// role step away from the forced actions, still sees those disabled with the reason.
func TestViewersGetStatusNotControls(t *testing.T) {
	t.Parallel()
	e := newPowerEnv(t, authz.RoleViewer)
	result(e.c.get("/servers/edge")).status(t, http.StatusOK).
		contains(t, "Actions need the operator role.").
		lacks(t, `class="hmenus"`, "btn-disabled", "why-off")
	result(e.c.get("/servers/edge")).status(t, http.StatusOK).
		lacks(t, `href="/servers/edge/power/`, "mi-off", "Needs the operator role.")

	op := newPowerEnv(t, authz.RoleOperator)
	result(op.c.get("/servers/edge")).status(t, http.StatusOK).
		contains(t, `class="hmenus"`, "Not configured for this server").lacks(t, "Actions need the operator role.")
	result(op.c.get("/servers/edge")).status(t, http.StatusOK).
		contains(t, `href="/servers/edge/power/graceful-shutdown"`, "Needs the admin role.")
}

func TestFanCardViewerHasNoDeadButton(t *testing.T) {
	t.Parallel()
	_, c, _ := fanSignedIn(t, authz.RoleViewer)
	result(c.get("/servers/r730xd/fan")).status(t, http.StatusOK).
		contains(t, "Fan leases need the operator role").lacks(t, "btn-disabled", "Start a lease")
}

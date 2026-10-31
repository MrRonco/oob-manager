package ui

import (
	"net/http"
	"strings"
	"testing"

	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
)

func TestServerPageIsAnomalyFirst(t *testing.T) {
	h, c := signedInOperator(t)
	v := h.fleet.servers[0]
	v.Tags = []string{"critical", "storage"}
	v.Snapshot = bmc.NewSnapshot(bmc.SnapshotParams{TakenAt: v.LastSuccess, PowerState: bmc.PowerOn, Health: bmc.HealthWarning,
		Temperatures: []bmc.Temperature{
			{Name: "CPU1 Temp", Context: "CPU", Celsius: bmc.ReadingOf(61), WarnAbove: bmc.ReadingOf(87), CritAbove: bmc.ReadingOf(92), Health: bmc.HealthOK},
			{Name: "System Board Inlet Temp", Context: "Intake", Celsius: bmc.ReadingOf(40), WarnAbove: bmc.ReadingOf(42), CritAbove: bmc.ReadingOf(47), Health: bmc.HealthOK},
		},
		Fans: []bmc.Fan{{Name: "System Board Fan1 RPM", Speed: bmc.ReadingOf(7200), Units: bmc.FanRPM, Health: bmc.HealthOK}},
		PSUs: []bmc.PSU{{Name: "PS1", Health: bmc.HealthOK}, {Name: "PS2", Health: bmc.HealthWarning}},
		Voltages: []bmc.Voltage{
			{Name: "System Board 3.3V PG", Volts: bmc.ReadingOf(1), Health: bmc.HealthOK},
			{Name: "CPU1 VCORE PG", Volts: bmc.ReadingOf(1), Health: bmc.HealthOK},
			{Name: "PS1 Voltage 1", Volts: bmc.ReadingOf(118), Health: bmc.HealthOK},
		},
		Power: bmc.PowerDraw{ConsumedWatts: bmc.ReadingOf(71), MaxWatts: bmc.ReadingOf(84)},
	})
	h.fleet.servers[0] = v
	ov := result(c.get("/servers/r730xd")).status(t, http.StatusOK).
		contains(t, "Critical server", "Verdict and exceptions", "Power supply PS2 reports Warning",
			">Inlet<", "Close: 2 °C below warning").
		lacks(t, "Actions</h2>", "not available yet", "1.00 V").rec.Body.String()
	if strings.Index(ov, "Verdict and exceptions") > strings.Index(ov, ">Status<") {
		t.Fatal("the verdict comes before the status (anomaly first)")
	}
	// Round-2 slice C: the tables are on the Sensors tab, in the same anomaly-first order.
	body := result(c.get("/servers/r730xd/sensors")).status(t, http.StatusOK).
		contains(t, "26 °C below warning", `class="hm-fill f-near w77"`, "Power-good signals: 2 of 2 good",
			"PS1 Voltage 1", "Fan1", `title="System Board Fan1 RPM"`, "Power control: not set up").
		lacks(t, "1.00 V").rec.Body.String()
	order := []string{">Temperatures<", `id="fans-h">Fans`, ">Voltage rails<"}
	last := -1
	for _, s := range order {
		i := strings.Index(body, s)
		if i < last {
			t.Fatalf("%q is out of order (anomaly first: verdict, status, temperatures, fans, rails)", s)
		}
		last = i
	}
	if strings.Index(body, ">Inlet<") > strings.Index(body, ">CPU1<") {
		t.Fatal("the near-threshold inlet must come before CPU1 (problems first)")
	}
}

func TestServerPageBMCLinkForOperatorsOnly(t *testing.T) {
	bmcURL := func(d *Deps) { d.BMCWebURL = func(string) string { return "https://192.0.2.70/" } }
	_, viewer := signedIn(t, bmcURL)
	result(viewer.get("/servers/r730xd")).lacks(t, "Open BMC web UI")
	h := newHarness(t, bmcURL)
	secret := h.addUser("ops", authz.RoleOperator, true)
	op := h.client("192.0.2.10")
	op.login("ops", secret)
	result(op.get("/servers/r730xd")).contains(t, "Open BMC web UI", "(192.0.2.70)", `rel="noreferrer"`)
}

// TestOldOperationsAddressMovesToTheHeaderMenus (plan 04 §11 item 8): the Operations tab is
// retired; its old address moves permanently to the server, whose header menus list
// the same actions, each a link or disabled with its reason.
func TestOldOperationsAddressMovesToTheHeaderMenus(t *testing.T) {
	_, c := signedIn(t)
	result(c.get("/servers/r730xd/operations")).status(t, http.StatusFound).location(t, "/servers/r730xd")
	result(c.get("/servers/r730xd/operations?x=1")).status(t, http.StatusFound).location(t, "/servers/r730xd?x=1")
	result(c.get("/servers/r730xd/operations?fan=started")).status(t, http.StatusFound).location(t, "/servers/r730xd/fan?fan=started")
	result(c.get("/servers/r730xd")).status(t, http.StatusOK).contains(t, "Actions need the operator role.").
		lacks(t, `class="hmenus"`, `aria-disabled="true"`, `class="bottombar"`) // a viewer gets status, not controls (audit R2-11)
	_, oc := signedInOperator(t)
	result(oc.get("/servers/r730xd")).status(t, http.StatusOK).contains(t, `class="hmenus"`, `class="bottombar"`,
		"Graceful restart", "Power cycle", "Fan boost", "Serial console", "Power control: not set up",
		`aria-disabled="true"`, `<body class="has-bottombar">`)
	result(c.get("/servers/nope/operations")).status(t, http.StatusFound).location(t, "/servers/nope")
	result(c.get("/servers/r730xd/logs?log=lifecycle")).status(t, http.StatusFound).
		location(t, "/servers/r730xd/events?log=lifecycle")
}

func TestInventoryHasCapabilities(t *testing.T) {
	_, c := signedIn(t)
	result(c.get("/servers/r730xd/inventory")).status(t, http.StatusOK).
		contains(t, "Capabilities", "System Event Log", "Power control", "Firmware")
}

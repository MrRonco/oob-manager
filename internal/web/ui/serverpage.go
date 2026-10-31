package ui

import (
	"net/http"
	"net/url"

	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
)

// maxServerEvents is the length of the Recent events panel on the server page.
const maxServerEvents = 5

// serverHead is the page head of every server tab: name, tags, identity line and the
// "Open BMC web UI" escape hatch (UX-24, operators and admins only: it shows an address).
type serverHead struct {
	Name, Tab, Identity, BMCURL, BMCHost string
	Tags                                 []string
	Maint                                *maintBadge // active maintenance window
	// The state chips under the name (round-2 slice C): power, health and data age.
	Power  string
	Health healthView
	Fresh  freshness
	// Menus are the header actions (Console ▾ · Power ▾ · More ▾), the same on every tab.
	Menus *serverMenus
}

// serverNav is the per-server tab bar.
type serverNav struct {
	ID, Tab  string
	Console  bool // the graphical console tab is offered to this user
	Serial   bool // the serial console tab is offered to this user
	Security bool // the BMC security checks are wired (tech_doc §31)
	History  bool // the sensor history is wired and the user may view it (tech_doc §39)
}

// verdictView is the first panel of the server page (UX-01): one sentence, then the
// remaining exceptions with anchors.
type verdictView struct {
	Health healthView
	Text   string
	Items  []attentionItem
	Panel  string // p-crit, p-warn, p-stale, p-ok
	// Live marks a transient state the page announces politely (role=status): an
	// expected BMC restart.
	Live bool
}

// nowView is the server Overview tab's Now panel: what is running or just happened
// (the last power action, a BMC restart, a maintenance window). The power and BMC
// status lines moved here from the retired Operations tab.
type nowView struct {
	Power, BMC *powerStatus
	Maint      *maintBadge
}

// Empty reports whether nothing is running.
func (n nowView) Empty() bool { return n.Power == nil && n.BMC == nil && n.Maint == nil }

// serverDetail is the server's Overview tab and, with the same data, its Sensors tab.
type serverDetail struct {
	Head          serverHead
	Nav           serverNav
	Summary       summaryRow
	TempUnit      string // "°C" or "°F", for the temperature table headers
	Refresh       refreshView
	HasSnapshot   bool
	Verdict       verdictView
	Temps         []tempRow
	Fans          []fanRow
	PSUs          []psuRow
	PSUCols       psuColumns
	Power         []kv
	Volt          voltagesView
	Sparks        sparkSet     // 24 h sparklines of the Status panel (tech_doc §39)
	Console       *consoleCard // nil when consoles are not wired
	Serial        *serialCard  // nil when the serial console is not wired
	Maint         *maintCard   // nil when maintenance mode is not wired
	Notes         *notesCard   // nil when notes are not wired
	Pinned        *noteView    // the pinned note, shown at the top
	Now           nowView
	BMC           bmcPanel // model, firmware and last restart (Overview tab's System panel)
	Events        []eventRow
	System        []kv
	HasInventory  bool
	PollTook      string
	InventoryNote string
}

func (s *server) serverPage(w http.ResponseWriter, r *http.Request, sess session) {
	v, ok := s.lookup(w, r)
	if !ok {
		return
	}
	det := s.detail(v, sess, "overview")
	if det.HasSnapshot {
		det.Sparks = s.sparksFor(r.Context(), v, det.Summary, sess)
	}
	det.Refresh = s.refreshFor(r, sess)
	_, det.Pinned = s.notesFor(v, sess)
	det.BMC = s.bmcPanelFor(v, sess)
	det.Now = nowView{Maint: det.Head.Maint, BMC: det.BMC.Status}
	if s.d.Power != nil {
		det.Now.Power = s.powerStatusFor(v.ID, sess.tf())
	}
	all, _ := s.fleetEvents(r.Context(), []ServerView{v}, []LogKind{LogSEL, LogLifecycle})
	det.Events = s.fleetRows(all[:min(len(all), maxServerEvents)], false, sess.tf())
	d := s.withRefresh(r, s.serverLayout(sess, v, v.Name, "", det))
	s.render(w, r, http.StatusOK, pageServer, d)
}

// sensorsPage is the Sensors tab: every temperature, fan, power supply and rail.
func (s *server) sensorsPage(w http.ResponseWriter, r *http.Request, sess session) {
	v, ok := s.lookup(w, r)
	if !ok {
		return
	}
	det := s.detail(v, sess, "sensors")
	det.Head = det.Head.tab("sensors")
	det.Refresh = s.refreshFor(r, sess)
	d := s.withRefresh(r, s.serverLayout(sess, v, v.Name+": sensors", "Sensors", det))
	s.render(w, r, http.StatusOK, pageSensors, d)
}

func (s *server) detail(v ServerView, sess session, tab string) serverDetail {
	sum := s.summarize(v, sess.view)
	d := serverDetail{Head: s.headFor(v, sess), Nav: s.navFor(v, sess, tab), Summary: sum,
		HasSnapshot: v.HasSnapshot, HasInventory: v.HasInventory, PollTook: fmtPollDuration(v.LastPollDuration),
		InventoryNote: s.overdueNote("Inventory", v.InventoryOverdue, v.InventoryAsOf, sess.tf())}
	if v.HasSnapshot {
		temps := sess.unit().convert(v.Snapshot.Temperatures())
		d.Temps = tempRows(temps, sess.unit())
		d.TempUnit = sess.unit().Symbol
		d.Fans = fanRows(v.Snapshot.Fans())
		if v.HasPrevious {
			d.Temps = withTempChanges(d.Temps, temps, sess.unit().convert(v.Previous.Temperatures()))
			d.Fans = withFanChanges(d.Fans, v.Snapshot.Fans(), v.Previous.Fans())
		}
		d.PSUs, d.PSUCols = psuRows(v.Snapshot.PSUs())
		d.Power = powerRows(v.Snapshot.Power())
		d.Volt = splitVoltages(v.Snapshot.Voltages())
	}
	d.Verdict = verdictOf(sum, v.Snapshot.Problems())
	if sum.Fresh.Stale {
		d = markStale(d)
	}
	if v.HasInventory {
		i := v.Inventory.Info()
		d.System = []kv{{"Model", i.Model}, {"Service tag", i.SKU}, {"BIOS", i.BIOSVersion}, {"BMC firmware", i.BMCFirmware}}
	}
	if s.d.Consoles != nil || s.d.KVM != nil {
		card := s.consoleCardFor(v, sess)
		d.Console = &card
	}
	if s.d.Serial != nil {
		card := s.serialCardFor(v, sess)
		d.Serial = &card
	}
	return d
}

func verdictOf(row summaryRow, problems []string) verdictView {
	items := attentionFor(row)
	for _, p := range problems {
		items = append(items, attentionItem{Text: "Not read in the last poll: " + p + ".", Health: healthOf(bmc.HealthUnknown)})
	}
	v := verdictView{Health: row.Health, Panel: "p-" + row.Health.Class}
	switch {
	case row.Fresh.Restarting:
		v.Text, v.Panel, v.Live, items = "BMC restarting · "+row.Fresh.Restart+".", "p-stale", true, nil
	case row.Fresh.NoData:
		v.Text, v.Panel = "No data yet: this server has never been polled successfully.", "p-stale"
	case row.Fresh.Stale:
		v.Text, v.Panel = "Data stale: no answer from the BMC for "+row.Fresh.Age+". Last known state: "+lastKnown(row.Health)+".", "p-stale"
	case len(items) > 0 && items[0].Server != "":
		first := items[0]
		v.Text, items = first.Text, items[1:]
		if row.Health.Class == "off" {
			v.Panel = "p-" + first.Health.Class // the power item's severity, not a plain "off"
		}
	case row.Health.Class == "ok":
		v.Text = "All reported sensors are within their limits."
	default:
		v.Text = "The BMC reports overall health " + row.Health.Label + "."
	}
	if v.Panel == "p-unknown" || v.Panel == "p-info" || v.Panel == "p-off" {
		v.Panel = ""
	}
	v.Items = items
	return v
}

// markStale returns d with every row's health replaced by the stale badge, so no
// sensor of a stale server reads "OK" (UI review F-02).
func markStale(d serverDetail) serverDetail {
	st := func(h healthView) healthView { return staleOf(h, false) }
	temps := make([]tempRow, 0, len(d.Temps))
	for _, r := range d.Temps {
		r.Health = st(r.Health)
		temps = append(temps, r)
	}
	fans := make([]fanRow, 0, len(d.Fans))
	for _, r := range d.Fans {
		r.Health = st(r.Health)
		fans = append(fans, r)
	}
	psus := make([]psuRow, 0, len(d.PSUs))
	for _, r := range d.PSUs {
		r.Health = st(r.Health)
		psus = append(psus, r)
	}
	volts := make([]voltageRow, 0, len(d.Volt.Analog))
	for _, r := range d.Volt.Analog {
		r.Health = st(r.Health)
		volts = append(volts, r)
	}
	d.Temps, d.Fans, d.PSUs, d.Volt.Analog = temps, fans, psus, volts
	return d
}

// headFor builds the page head; the BMC link needs the operator role (it shows an address).
func (s *server) headFor(v ServerView, sess session) serverHead {
	row := s.summarize(v, sess.view)
	h := serverHead{Name: v.Name, Tags: v.Tags, Maint: row.Maint, Power: row.Power, Health: row.Health, Fresh: row.Fresh}
	if v.HasInventory {
		i := v.Inventory.Info()
		h.Identity = i.Model
		if i.BMCFirmware != "" {
			h.Identity = joinDot(h.Identity, "BMC firmware "+i.BMCFirmware)
		}
	}
	if s.d.Authorize(sess.id.Principal(), authz.PowerOn, true) == nil {
		if u := s.d.BMCWebURL(v.ID); u != "" {
			if p, err := url.Parse(u); err == nil && p.Scheme == "https" {
				h.BMCURL, h.BMCHost = u, p.Hostname()
			}
		}
	}
	h.Menus = s.menusFor(v, h, sess)
	return h
}

func joinDot(a, b string) string {
	if a == "" {
		return b
	}
	return a + " · " + b
}

// navFor marks the tab and offers Console only when it is configured for this server and
// the user's role may open it.
func (s *server) navFor(v ServerView, sess session, tab string) serverNav {
	n := serverNav{ID: v.ID, Tab: tab, Security: s.d.Security != nil,
		History: s.historyOn() && s.d.Authorize(sess.id.Principal(), authz.ViewHistory, true) == nil}
	if s.d.Consoles != nil && s.d.Consoles.Status(v.ID).Configured {
		n.Console = s.d.Authorize(sess.id.Principal(), authz.ConsoleVNC, true) == nil
	}
	if s.d.Serial != nil && s.d.Serial.Status(v.ID).Configured {
		n.Serial = s.d.Authorize(sess.id.Principal(), authz.ConsoleSerial, true) == nil
	}
	return n
}

// tab names the server sub-page in the h1 ("server-a: logs"), which is also the title.
func (h serverHead) tab(name string) serverHead {
	h.Tab = name
	return h
}

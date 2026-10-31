package ui

import (
	"oob-manager/internal/authz"
)

// serverMenus are the persistent header actions of every server tab (plan 04 §11 item 8;
// round-2 slice C): Console ▾ · Power ▾ · More ▾, in that order and place, as
// <details> menus (no script needed). On phones the same menus sit in a sticky bottom bar
// (item 9). A role that can use none of the actions (a viewer) gets Note instead: status,
// not controls (audit R2-11). Every item is a link to a page that checks the role
// itself; an item that cannot be used stays visible with the reason.
type serverMenus struct {
	Note                 string
	Console, Power, More []menuItem
}

// menuItem is one menu entry: a link (Href), or disabled with its reason (Why). Sep
// starts a new group; Danger marks a forced or service-impacting action.
type menuItem struct {
	Label, Sub, Icon, Href, Why string
	Sep, Danger                 bool
}

// menusFor builds the three menus for v; nil only when there is nothing to show.
func (s *server) menusFor(v ServerView, head serverHead, sess session) *serverMenus {
	p := sess.id.Principal()
	canAct := false
	for _, a := range []authz.Action{authz.PowerOn, authz.FanLeaseCreate, authz.ConsoleVNC, authz.ServerMaintenance, authz.ServerNotes} {
		canAct = canAct || s.d.Authorize(p, a, true) == nil
	}
	if !canAct {
		return &serverMenus{Note: "Actions need the operator role."}
	}
	return &serverMenus{Console: s.consoleItems(v, sess), Power: s.powerItems(v, sess), More: s.moreItems(v, head, sess)}
}

func (s *server) consoleItems(v ServerView, sess session) []menuItem {
	gfx := menuItem{Label: "Graphical console", Sub: "The BMC's screen, keyboard and mouse", Icon: "monitor"}
	switch {
	case s.d.Consoles == nil || !s.d.Consoles.Status(v.ID).Configured:
		gfx.Why = "Not configured for this server"
	case !s.allowed(sess, authz.ConsoleVNC):
		gfx.Why = "Needs the admin role"
	default:
		gfx.Href = "/servers/" + v.ID + "/console"
	}
	ser := menuItem{Label: "Serial console", Sub: "Text, screen-reader friendly", Icon: "square-terminal"}
	switch {
	case s.d.Serial == nil || !s.d.Serial.Status(v.ID).Configured:
		ser.Why = "Not configured for this server"
	case !s.allowed(sess, authz.ConsoleSerial):
		ser.Why = "Needs the admin role"
	default:
		ser.Href = "/servers/" + v.ID + "/serial"
	}
	return []menuItem{gfx, ser}
}

// powerItems are the power actions (safe, then forced) and Restart BMC, each a link to
// its confirm page or disabled with the reason.
func (s *server) powerItems(v ServerView, sess session) []menuItem {
	p := sess.id.Principal()
	var safe, forced []opAction
	if s.d.Power != nil {
		safe, forced = s.powerActions(v, p, false), s.powerActions(v, p, true)
	} else {
		safe, forced = withWhy(defaultOps(false), "Power control: not set up"), withWhy(defaultOps(true), "Power control: not set up")
	}
	var out []menuItem
	for i, a := range append(safe, forced...) {
		it := menuItem{Label: a.Label, Sub: a.Detail, Icon: "power", Why: a.Why, Sep: i == len(safe), Danger: a.Forced}
		if a.Href != "" {
			it.Label, it.Href = a.Label+"…", a.Href
		}
		out = append(out, it)
	}
	bmc := s.bmcPanelFor(v, sess)
	it := menuItem{Label: "Restart BMC", Sub: "Management controller only; the host keeps running", Icon: "refresh-cw", Sep: true,
		Danger: true, Why: bmc.Why}
	switch {
	case bmc.Hidden:
		it.Why = "Needs the admin role"
	case bmc.Href != "":
		it.Label, it.Href = "Restart BMC…", bmc.Href
	}
	return append(out, it)
}

// defaultOps are the power actions as listed when power control is not wired.
func defaultOps(forced bool) []opAction {
	if forced {
		return []opAction{{Label: "Force off", Detail: "Cuts power at once. Unsaved data is lost.", Forced: true},
			{Label: "Power cycle", Detail: "Off, then on again. Unsaved data is lost.", Forced: true},
			{Label: "Force restart", Detail: "Resets the server at once.", Forced: true}}
	}
	return []opAction{{Label: "Power on", Detail: "Starts the server."},
		{Label: "Graceful shutdown", Detail: "Asks the operating system to shut down."},
		{Label: "Graceful restart", Detail: "Asks the operating system to restart."}}
}

func (s *server) moreItems(v ServerView, head serverHead, sess session) []menuItem {
	id := v.ID
	fan := menuItem{Label: "Fan boost…", Sub: "A minimum fan speed for a while", Icon: "fan", Href: fanPath(id)}
	if s.d.Fans == nil {
		fan.Label, fan.Href, fan.Why = "Fan boost", "", "Fan control: not set up"
	} else if _, ok := s.d.Fans.Policy(id); !ok {
		fan.Label, fan.Href, fan.Why = "Fan boost", "", "Fan control: off for this server"
	}
	maintItem := menuItem{Label: "Start maintenance…", Sub: "Pause health alerts", Icon: "wrench"}
	switch {
	case s.d.Maintenance == nil || !s.d.Maintenance.Available():
		maintItem.Why = notSetUp
	case !s.allowed(sess, authz.ServerMaintenance):
		maintItem.Why = "Needs the operator role"
	case head.Maint != nil:
		maintItem.Label, maintItem.Href = "Maintenance…", "/servers/"+id+"/activity#maint-h"
	default:
		maintItem.Href = "/servers/" + id + "/maintenance/new"
	}
	note := menuItem{Label: "Add note…", Icon: "sticky-note"}
	switch {
	case s.d.Maintenance == nil || !s.d.Maintenance.Available():
		note.Why = notSetUp
	case !s.allowed(sess, authz.ServerNotes):
		note.Why = "Needs the operator role"
	default:
		note.Href = "/servers/" + id + "/notes/new"
	}
	out := []menuItem{fan, maintItem, note}
	if head.BMCURL != "" {
		out = append(out, menuItem{Label: "Open BMC web UI", Sub: head.BMCHost, Icon: "external-link", Href: head.BMCURL, Sep: true})
	}
	if s.allowed(sess, authz.AdminServers) && s.d.Servers != nil {
		out = append(out, menuItem{Label: "Server settings", Sub: "Connection and credentials", Icon: "settings",
			Href: "/settings/servers/" + id, Sep: head.BMCURL == ""})
	}
	return out
}

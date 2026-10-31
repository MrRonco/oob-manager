package ui

import "oob-manager/internal/authz"

// actionRow is one entry of the inventory page's "Capabilities" list (UI review F-15):
// whether the BMC supports the action, whether this installation offers it on this
// server, and whether the viewer's role may use it, so "not supported", "not set up" and
// "not permitted" are never confused.
type actionRow struct {
	Name    string
	Support string
	Offered string
	Access  string
}

// actionSpec ties an action to its authz rule and capability. support is nil when the
// action does not depend on what the BMC reports (fan leases: the mode decides).
type actionSpec struct {
	name    string
	action  authz.Action
	role    string
	support func(ServerView) (supported, known bool)
}

// offeredInMenus is the Offered text of an action that is usable from the server menus.
const offeredInMenus = "In the server menus (Console, Power, More)."

func actionSpecs() []actionSpec {
	return []actionSpec{
		{"Power control", authz.PowerOn, "operator", func(v ServerView) (bool, bool) {
			return len(v.Capabilities.ResetTypes()) > 0, v.HasCapabilities
		}},
		{"Fan lease", authz.FanLeaseCreate, "operator", nil},
		{"Serial console", authz.ConsoleSerial, "admin", func(v ServerView) (bool, bool) {
			return v.Capabilities.Flags().SerialConsole, v.HasCapabilities
		}},
		{"Graphical console", authz.ConsoleVNC, "admin", func(v ServerView) (bool, bool) {
			lic := v.HasInventory && v.Inventory.License().GraphicalConsole
			return v.Capabilities.Flags().GraphicalConsole || lic, v.HasCapabilities || v.HasInventory
		}},
	}
}

// actionRows describes each action for principal p on server v. The consoles have their
// own cards when they are wired, so they are listed here only when they are not.
func (s *server) actionRows(v ServerView, p authz.Principal) []actionRow {
	specs := actionSpecs()
	out := make([]actionRow, 0, len(specs))
	for _, sp := range specs {
		if sp.action == authz.ConsoleVNC && (s.d.Consoles != nil || s.d.KVM != nil) {
			continue // the graphical console has its own card (P5)
		}
		if sp.action == authz.ConsoleSerial && s.d.Serial != nil {
			continue // the serial console has its own card (P4)
		}
		row := actionRow{Name: sp.name, Offered: s.offered(v, sp.action), Access: "Your role may use it."}
		if sp.support != nil {
			row.Support = supportText(sp.support(v))
		}
		if s.d.Authorize(p, sp.action, true) != nil {
			row.Access = "Needs the " + sp.role + " role."
		}
		out = append(out, row)
	}
	return out
}

// offered says whether this installation offers action a on server v.
func (s *server) offered(v ServerView, a authz.Action) string {
	switch {
	case a == authz.PowerOn && s.d.Power != nil:
		if !s.d.Power.Info(v.ID).Operator {
			return "Needs an operator BMC account (credentials.operator in the config)."
		}
		return offeredInMenus
	case a == authz.FanLeaseCreate && s.d.Fans != nil:
		if _, ok := s.d.Fans.Policy(v.ID); !ok {
			return "Off for this server (fan.mode: none)."
		}
		return offeredInMenus
	default:
		return notSetUp
	}
}

func supportText(supported, known bool) string {
	switch {
	case !known:
		return "Support not determined yet."
	case supported:
		return "Supported by this BMC."
	default:
		return "Not supported by this BMC."
	}
}

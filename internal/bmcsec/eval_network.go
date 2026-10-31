package bmcsec

import "oob-manager/internal/bmc"

func networkEntries() []entry {
	return []entry{
		{check: Check{ID: "net.ip_filter", Group: GroupNetwork, Title: "IP filter",
			Why: "A BMC that answers every address on its network is exposed to every compromised machine there. Allowing only the " +
				"management hosts shrinks that to a few.",
			Fix: "Allow only the management hosts, oob-manager's own address included, with the BMC's IP filter or a firewall in front " +
				"of the management network.",
			Dell: "IP blocking range (iDRAC.IPBlocking.RangeEnable, RangeAddr, RangeMask). Include oob-manager's address, or polling stops."},
			eval: ipFilter},
		{check: Check{ID: "net.dhcp", Group: GroupNetwork, Title: "Address assignment",
			Why: "A BMC that takes its address from DHCP can move when the lease changes. oob-manager pins the address, so it would lose " +
				"the BMC, and so would firewall rules or filters keyed to it.",
			Fix:  "Give the BMC a static address or a DHCP reservation.",
			Dell: "racadm set iDRAC.IPv4.DHCPEnable 0, with a static address."},
			eval: dhcp},
		{check: Check{ID: "net.ipv6", Group: GroupNetwork, Title: "IPv6",
			Why:  "With IPv6 on, the BMC has addresses that firewall rules and filters written for IPv4 may not cover.",
			Fix:  "Turn IPv6 off on the BMC if you do not use it, or make sure the firewall and the BMC's filters cover its IPv6 addresses.",
			Dell: "racadm set iDRAC.IPv6.Enable 0."},
			eval: ipv6},
	}
}

func ipFilter(c evalCtx) outcome {
	n := c.p.Redfish.Network
	switch {
	case !n.IPFilter.Known && c.p.Redfish.Attributes.State == bmc.ReadNotTried:
		return out(Unknown, "", "This BMC does not report an address filter over Redfish; a firewall in front of it protects it as well.")
	case !n.IPFilter.Known:
		return missing("the IP filter", c.p.Redfish.Attributes)
	case !n.IPFilter.Value:
		return out(Warn, "off", "Any address can reach the BMC: the IP filter is off"+from(n.IPFilter.Source)+".")
	case n.IPFilterRange.Known:
		return out(Pass, "", "Only "+n.IPFilterRange.Value+" may connect"+from(n.IPFilterRange.Source)+".")
	default:
		return out(Pass, "", "The IP filter is on"+from(n.IPFilter.Source)+".")
	}
}

func dhcp(c evalCtx) outcome {
	f := c.p.Redfish.Network.DHCP
	switch {
	case !f.Known:
		return missing("how the BMC gets its address", c.p.Redfish.Protocols.Read, c.p.Redfish.Attributes)
	case f.Value:
		return out(Info, "dhcp", "The address comes from DHCP"+from(f.Source)+".")
	default:
		return out(Pass, "", "Static address"+from(f.Source)+".")
	}
}

func ipv6(c evalCtx) outcome {
	f := c.p.Redfish.Network.IPv6
	switch {
	case !f.Known:
		return missing("whether IPv6 is on", c.p.Redfish.Attributes)
	case f.Value:
		return out(Info, "on", "IPv6 is on"+from(f.Source)+".")
	default:
		return out(Pass, "", "IPv6 is off"+from(f.Source)+".")
	}
}

package main

import (
	"net"
	"net/netip"
	"net/url"

	"oob-manager/internal/config"
	"oob-manager/internal/egress"
)

const lanAdvice = `: oob-manager is meant for a management LAN only; publish it on a private ` +
	`address and put any remote access behind a VPN or an identity-aware proxy ` +
	`(deploy/README.md, "Networking: keep it on the LAN")`

// exposureNotes warns at start when config.yaml binds or advertises the console on a
// public IP address. Host names are not resolved: the check never sends a DNS query.
func exposureNotes(cfg config.Config) []startNote {
	var notes []startNote
	if host, _, err := net.SplitHostPort(cfg.Listen); err == nil {
		if a, ok := publicLiteral(host); ok {
			notes = append(notes, warnNote("listen "+a.String()+" is a public address"+lanAdvice))
		}
	}
	if u, err := url.Parse(cfg.PublicURL); err == nil && cfg.PublicURL != "" {
		if a, ok := publicLiteral(u.Hostname()); ok {
			notes = append(notes, warnNote("public_url "+a.String()+" is a public address"+lanAdvice))
		}
	}
	return notes
}

// publicLiteral reports whether host is an IP literal of a public unicast address,
// returned unmapped (an IPv4-mapped IPv6 address is judged and shown as its IPv4).
func publicLiteral(host string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	return a, egress.PublicUnicast(a)
}

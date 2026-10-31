package config

import (
	"slices"
	"strings"
	"unicode"
)

// Limits of power.impact (shown as the "what goes down" list of the power confirm page).
const (
	MaxImpactLines = 8
	MaxImpactLen   = 200
)

// PowerConfig is optional per-server context for power actions. It changes what the
// confirm page says and which actions need the typed server name; it never enables an
// action (that needs credentials.operator and the BMC's own AllowableValues).
type PowerConfig struct {
	// SelfHost marks the machine oob-manager itself runs on: the confirm page warns that
	// the console goes offline, and every action that stops the host needs the typed name.
	SelfHost bool `yaml:"self_host"`
	// Impact lists what goes down with the server ("Network gateway: all internet
	// access drops"), one plain-text line each.
	Impact []string `yaml:"impact"`
}

func (p PowerConfig) clone() PowerConfig {
	p.Impact = slices.Clone(p.Impact)
	return p
}

func validatePower(p problems, prefix string, c PowerConfig) problems {
	if len(c.Impact) > MaxImpactLines {
		p = p.add("%s: power.impact has %d lines, at most %d allowed", prefix, len(c.Impact), MaxImpactLines)
	}
	for i, line := range c.Impact {
		switch {
		case strings.TrimSpace(line) == "" || len(line) > MaxImpactLen:
			p = p.add("%s: power.impact[%d] must be 1 to %d bytes", prefix, i, MaxImpactLen)
		case strings.ContainsFunc(line, func(r rune) bool { return !unicode.IsPrint(r) }):
			p = p.add("%s: power.impact[%d] must be plain printable text", prefix, i)
		}
	}
	return p
}

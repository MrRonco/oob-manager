package config

import (
	"strings"
	"testing"
)

// withPower adds a power block to the first server (r730xd).
func withPower(block string) string {
	return strings.Replace(validYAML(), "    console: { serial: bmcssh, graphical: vnc }\n",
		"    console: { serial: bmcssh, graphical: vnc }\n    power: "+block+"\n", 1)
}

func TestPowerConfig(t *testing.T) {
	cfg := mustParse(t, withPower(`{ self_host: true, impact: ["Storage: every share goes offline", "Containers stop"] }`))
	s, _ := cfg.Server("r730xd")
	if !s.Power.SelfHost || len(s.Power.Impact) != 2 || s.Power.Impact[0] != "Storage: every share goes offline" {
		t.Fatalf("power = %+v", s.Power)
	}
	s.Power.Impact[0] = "mutated"
	if again, _ := cfg.Server("r730xd"); again.Power.Impact[0] == "mutated" {
		t.Fatal("Server() leaked the impact slice")
	}
	other, _ := cfg.Server("r240")
	if other.Power.SelfHost || other.Power.Impact != nil {
		t.Fatalf("default power = %+v", other.Power)
	}
}

func TestPowerConfigRejected(t *testing.T) {
	many := `[` + strings.TrimSuffix(strings.Repeat(`"a", `, MaxImpactLines+1), ", ") + `]`
	for name, block := range map[string]string{
		"too many":    `{ impact: ` + many + ` }`,
		"too long":    `{ impact: ["` + strings.Repeat("x", MaxImpactLen+1) + `"] }`,
		"empty":       `{ impact: [""] }`,
		"control":     `{ impact: ["a\tb"] }`,
		"unknown key": `{ selfhost: true }`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(withPower(block)))
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "power") {
				t.Fatalf("err = %v, want a power problem", err)
			}
		})
	}
}

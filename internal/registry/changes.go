package registry

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/store"
)

// Change is one field of an audit row's "changes" list. Credential values never appear:
// a credential change reads "[redacted] v3" → "[redacted] v4".
type Change struct {
	Field  string
	Before string
	After  string
}

// fieldsOf maps a row to the audited (non-secret) field values.
func fieldsOf(r store.ServerRow) map[string]string {
	return map[string]string{
		"name": r.Name, "tags": strings.Join(r.Tags, ", "), "bmc.kind": r.Kind, "bmc.address": r.Address,
		"bmc.port": strconv.Itoa(r.Port), "tls_pin_sha256": r.TLSPin, "console.vnc.tls_pin_sha256": r.VNCPin,
		"ssh_host_key": r.SSHHostKey, "fan.mode": r.FanMode, "fan.safe_min_pct": strconv.Itoa(r.FanSafeMinPct),
		"fan.max_lease": durText(r.FanMaxLease), "console.serial": r.ConsoleSerial,
		"console.graphical": r.ConsoleGraphical, "console.vnc.port": strconv.Itoa(r.VNCPort),
		"console.ssh.port": strconv.Itoa(r.SSHPort), "power.self_host": strconv.FormatBool(r.PowerSelfHost),
		"power.impact": strings.Join(r.PowerImpact, " | "), "poll.interval": durText(r.PollInterval),
		"enabled": strconv.FormatBool(r.Enabled),
	}
}

// fieldOrder is the audit order of fieldsOf's keys; every key is public (no secret).
func fieldOrder() []string {
	return []string{"name", "tags", "bmc.kind", "bmc.address", "bmc.port", "tls_pin_sha256",
		"console.vnc.tls_pin_sha256", "ssh_host_key", "fan.mode", "fan.safe_min_pct", "fan.max_lease",
		"console.serial", "console.graphical", "console.vnc.port", "console.ssh.port", "power.self_host",
		"power.impact", "poll.interval", "enabled"}
}

func durText(d time.Duration) string {
	if d == 0 {
		return ""
	}
	return d.String()
}

// diffRows lists the audited fields that differ between two rows, in fieldOrder.
func diffRows(before, after store.ServerRow) []Change {
	b, a := fieldsOf(before), fieldsOf(after)
	var out []Change
	for _, k := range fieldOrder() {
		if b[k] != a[k] {
			out = append(out, Change{Field: k, Before: b[k], After: a[k]})
		}
	}
	return out
}

// credChange is the redacted audit form of a credential replacement.
func credChange(slot string, before, after int) Change {
	ver := func(v int) string {
		if v == 0 {
			return "not set"
		}
		return fmt.Sprintf("%s v%d", audit.Redacted, v)
	}
	return Change{Field: "credentials." + slot, Before: ver(before), After: ver(after)}
}

// params is the audit form: {"target":"server:<id>","rev":n,"changes":[…]} plus extra.
func params(id string, changes []Change, rev int64, extra map[string]any) map[string]any {
	list := make([]any, 0, len(changes))
	for _, c := range changes {
		list = append(list, map[string]any{"field": c.Field, "before": c.Before, "after": c.After})
	}
	out := map[string]any{"target": "server:" + id, "changes": list}
	if rev > 0 {
		out["rev"] = rev
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

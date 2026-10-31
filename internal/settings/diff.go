package settings

import (
	"slices"
	"strconv"

	"oob-manager/internal/audit"
	"oob-manager/internal/config"
)

// Change is one field of an audit row's "changes" list.
type Change struct {
	Field  string
	Before string
	After  string
}

// params is the audit form of a change list: {"field","before","after"} objects.
func params(target string, changes []Change, extra map[string]any) map[string]any {
	list := make([]any, 0, len(changes))
	for _, c := range changes {
		list = append(list, map[string]any{"field": c.Field, "before": c.Before, "after": c.After})
	}
	out := map[string]any{"target": target, "changes": list}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// Diff lists the fields that differ between before and after, in keys order. Values
// of fields not in public are replaced by audit.Redacted (fail closed): a section that
// later adds a secret field must list every readable field, and anything it forgets
// can never leak its value into the audit chain.
func Diff(keys []string, before, after map[string]string, public func(string) bool) []Change {
	var out []Change
	for _, k := range keys {
		b, a := before[k], after[k]
		if a == b {
			continue
		}
		if !public(k) {
			b, a = audit.Redacted, audit.Redacted
		}
		out = append(out, Change{Field: k, Before: b, After: a})
	}
	return out
}

// generalPublic is the redaction allow-list of the General section: every key (none
// is secret).
func generalPublic(key string) bool { return slices.Contains(config.GeneralKeys(), key) }

// generalValues maps every General key to its display value.
func generalValues(g config.General) map[string]string {
	out := map[string]string{}
	for _, s := range GeneralSpecs() {
		v := s.display(get(g, s.Key))
		if _, err := strconv.Atoi(v); err == nil {
			v += unitSuffix(s.Unit)
		}
		out[s.Key] = v
	}
	return out
}

func unitSuffix(u Unit) string {
	switch u {
	case UnitSeconds:
		return " s"
	case UnitMinutes:
		return " min"
	case UnitHours:
		return " h"
	case UnitDays:
		return " d"
	default:
		return ""
	}
}

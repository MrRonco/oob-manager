package bmc

import (
	"slices"
	"strings"
	"time"
)

// Severity of a log entry.
type Severity string

// Severities.
const (
	SeverityUnknown  Severity = "Unknown"
	SeverityOK       Severity = "OK"
	SeverityWarning  Severity = "Warning"
	SeverityCritical Severity = "Critical"
)

// ParseSeverity maps a BMC-supplied severity string (case-insensitive).
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ok":
		return SeverityOK
	case "warning":
		return SeverityWarning
	case "critical":
		return SeverityCritical
	default:
		return SeverityUnknown
	}
}

// Event is one SEL / Lifecycle log entry. All strings are BMC-supplied and untrusted:
// render them escaped, never as HTML.
type Event struct {
	ID         string
	Created    time.Time // zero when the BMC sent no parseable timestamp
	Severity   Severity
	Message    string
	MessageID  string
	EntryType  string // "SEL", "Oem", ...
	EntryCode  string // "Assert", "Deassert", ...
	SensorType string
}

// EventLog is an immutable list of entries read from one log.
type EventLog struct {
	source   string
	entries  []Event
	complete bool
}

// NewEventLog copies entries. complete is false when paging stopped early.
func NewEventLog(source string, entries []Event, complete bool) EventLog {
	return EventLog{source: source, entries: slices.Clone(entries), complete: complete}
}

// Source is the Redfish URI the entries were read from.
func (l EventLog) Source() string { return l.source }

// Entries returns a copy of the entries, in BMC order (iDRAC: newest first).
func (l EventLog) Entries() []Event { return slices.Clone(l.entries) }

// Len is the number of entries.
func (l EventLog) Len() int { return len(l.entries) }

// Complete is false when not every page could be read.
func (l EventLog) Complete() bool { return l.complete }

// Package registry is the effective server registry (settings_design.md §2, slice S3):
// the servers written in config.yaml plus the servers an admin manages in the browser
// (the servers table), resolved with file > database precedence. A database server
// whose id is also in the file is shadowed: ignored, logged and audited once per start.
// File servers are read-only in the browser; settings.locked: [servers] makes the whole
// section read-only.
//
// Database servers pass exactly the config.yaml validator (config.ValidateServer) plus
// the BMC address policy (internal/netpolicy). Their credentials are sealed with
// internal/secrets/credstore, bound to the server's kind, address and port, so moving a
// server clears them. Service applies every change in one transaction with its audit row
// and notifies a subscriber, which rebuilds the pollers and features (fleet.Apply) without
// a restart.
package registry

import (
	"slices"
	"time"

	"oob-manager/internal/config"
	"oob-manager/internal/secrets/credstore"
)

// Source is where a server is defined.
type Source string

// Sources.
const (
	SourceFile Source = "file" // config.yaml: read-only in the browser
	SourceDB   Source = "db"   // managed in Settings → Servers
)

// CredInfo describes a stored credential without its value ("set · v3 · date by user").
type CredInfo struct {
	Slot      credstore.Slot
	Version   int
	CreatedAt time.Time
	CreatedBy string
}

// Entry is one server of the registry. It is a value; nobody modifies a published one.
type Entry struct {
	// Server is the normalised server. For a database server, Credentials holds the slot
	// names of the credentials that are stored ("readonly", "operator", "vnc").
	Server  config.Server
	Source  Source
	Enabled bool // file servers are always enabled
	// Shadowed: a database row whose id is also in config.yaml (the file wins).
	Shadowed bool
	// Problems are why a database server cannot run (validation, address policy,
	// missing credentials); an enabled server with problems is not polled.
	Problems []string
	// PollInterval overrides poll.interval for this server (0: the app's).
	PollInterval time.Duration
	Creds        []CredInfo
	Rev          int64
	CreatedAt    time.Time
	CreatedBy    string
	UpdatedAt    time.Time
	UpdatedBy    string
}

// Active reports whether the server is polled and its features are built.
func (e Entry) Active() bool {
	if e.Source == SourceFile {
		return true
	}
	return e.Enabled && !e.Shadowed && len(e.Problems) == 0
}

// Cred returns the stored credential of slot.
func (e Entry) Cred(slot credstore.Slot) (CredInfo, bool) {
	i := slices.IndexFunc(e.Creds, func(c CredInfo) bool { return c.Slot == slot })
	if i < 0 {
		return CredInfo{}, false
	}
	return e.Creds[i], true
}

func (e Entry) clone() Entry {
	e.Server = config.Normalise(e.Server)
	e.Problems = slices.Clone(e.Problems)
	e.Creds = slices.Clone(e.Creds)
	return e
}

// Effective is the resolved registry: file servers in file order, then database
// servers by id (shadowed rows included, flagged). It is a value.
type Effective struct {
	entries []Entry
	// Locked: settings.locked lists servers; the section is read-only in the browser.
	Locked bool
	// Warnings are for the startup log and the Servers page (shadowed rows, rows that
	// cannot run).
	Warnings []string
}

// Entries returns every entry (a fresh slice of copies).
func (e Effective) Entries() []Entry {
	out := make([]Entry, 0, len(e.entries))
	for _, x := range e.entries {
		out = append(out, x.clone())
	}
	return out
}

// Entry returns the entry that wins for id (the file one when both exist).
func (e Effective) Entry(id string) (Entry, bool) {
	for _, x := range e.entries {
		if x.Server.ID == id && !x.Shadowed {
			return x.clone(), true
		}
	}
	return Entry{}, false
}

// DBEntry returns the database row for id, even when it is shadowed.
func (e Effective) DBEntry(id string) (Entry, bool) {
	for _, x := range e.entries {
		if x.Server.ID == id && x.Source == SourceDB {
			return x.clone(), true
		}
	}
	return Entry{}, false
}

// Active returns the entries that run (polled, features built), in display order.
func (e Effective) Active() []Entry {
	var out []Entry
	for _, x := range e.entries {
		if x.Active() {
			out = append(out, x.clone())
		}
	}
	return out
}

// Editable reports whether the browser may change server id (a database server in an
// unlocked section; a shadowed row may only be deleted).
func (e Effective) Editable(id string) bool {
	x, ok := e.DBEntry(id)
	return ok && !e.Locked && !x.Shadowed
}

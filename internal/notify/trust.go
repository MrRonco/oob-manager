package notify

import (
	"time"

	"oob-manager/internal/audit"
)

// What a trust event is about (TrustEvent's what). The poller's certificate pin is
// reported by the detector ("TLS certificate"); the console and Test connection checks
// below report the others (settings slice S3, tech_doc §27).
const (
	TrustTLS    = "TLS certificate"
	TrustVNC    = "VNC certificate"
	TrustSSHKey = "SSH host key"
)

// trustCooldown keeps a repeated mismatch of the same check quiet: every refused
// console attempt or Test connection would otherwise page again.
const trustCooldown = 15 * time.Minute

// Trust reports the outcome of a pinned-key check outside polling: ok=false is a
// mismatch (critical, once per cooldown); ok=true resolves an earlier mismatch and is
// silent otherwise. The S3 Test connection calls it; console stops reach it through
// the audit trail (translateTrust).
func (t *Tap) Trust(serverID, what string, ok bool) {
	if e, send := t.trust(serverID, what, ok); send {
		t.emit(e)
	}
}

func (t *Tap) trust(serverID, what string, ok bool) (Event, bool) {
	if serverID == "" {
		return Event{}, false
	}
	key := "trust/" + serverID + "/" + what
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if ok {
		if !t.mismatch[key] {
			return Event{}, false
		}
		delete(t.mismatch, key)
		delete(t.quiet, key)
		return TrustEvent(serverID, t.name(serverID), what, true, now), true
	}
	t.mismatch[key] = true
	if until, quiet := t.quiet[key]; quiet && now.Before(until) {
		return Event{}, false
	}
	t.quiet[key] = now.Add(trustCooldown)
	return TrustEvent(serverID, t.name(serverID), what, false, now), true
}

// translateTrust maps console stops: a serial connection refused for its host key or a
// graphical one refused for its VNC certificate pin is a mismatch; a session that ran
// resolves an earlier one.
func (t *Tap) translateTrust(r record) (Event, bool) {
	what := map[string]string{"console.serial.stop": TrustSSHKey, "console.vnc.stop": TrustVNC}[r.action]
	if what == "" {
		return Event{}, false
	}
	switch {
	case r.result == audit.ResultOK:
		return t.trust(r.server, what, true)
	case r.result == audit.ResultError && (r.class == "host_key" || r.class == "tls_pin"):
		return t.trust(r.server, what, false)
	}
	return Event{}, false
}

// Keep forgets the trust state of every server not in ids (removed in Settings →
// Servers or from config.yaml), so a server re-added with the same id starts clean.
func (t *Tap) Keep(ids []string) {
	known := make(map[string]bool, len(ids))
	for _, id := range ids {
		known[id] = true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for key := range t.mismatch {
		if !known[trustServer(key)] {
			delete(t.mismatch, key)
			delete(t.quiet, key)
		}
	}
}

// trustServer is the server id of a "trust/<id>/<what>" key (ids never hold "/").
func trustServer(key string) string {
	rest := key[len("trust/"):]
	for i := range len(rest) {
		if rest[i] == '/' {
			return rest[:i]
		}
	}
	return rest
}

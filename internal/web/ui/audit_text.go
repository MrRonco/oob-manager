package ui

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"oob-manager/internal/store"
)

// Audit entries as sentences (UX-11): who did what to which target. The action code
// stays visible as a secondary chip; the parameters become a key/value list.

// auditVerbs maps an action to its sentence; %s is the target ("" when the action has
// none). Unknown actions fall back to "who: action".
var auditVerbs = map[string]string{ //nolint:gosec // G101: sentence templates, not credentials
	"auth.login":               "signed in",
	"auth.logout":              "signed out",
	"auth.stepup":              "confirmed with the authenticator (step-up)",
	"auth.enrol":               "finished account setup with a one-time link",
	"auth.totp.enroll":         "confirmed a new authenticator",
	"token.create":             "created API token %s",
	"token.revoke":             "revoked an API token",
	"admin.user.create":        "created user %s",
	"admin.user.role":          "changed the role of %s",
	"admin.user.disable":       "disabled the account of %s",
	"admin.user.enable":        "enabled the account of %s",
	"admin.user.reset_totp":    "reset the authenticator of %s",
	"admin.session.revoke":     "ended a session of %s",
	"admin.session.revoke_all": "ended all sessions of %s",
	"admin.audit.verify":       "verified the audit chain",
	"admin.bootstrap":          "created the first admin account %s",
	"admin.totp_confirmed":     "confirmed the authenticator of %s",
	"admin.totp_reset":         "reset the authenticator of %s from the command line",
	"console.vnc.start":        "opened the graphical console of %s",
	"console.vnc.stop":         "closed the graphical console of %s",
	"console.vnc.takeover":     "took over the graphical console of %s",
	"console.kvm_launch":       "opened the native BMC console of %s",
	"admin.general.update":     "changed the general settings",
	"admin.general.reset":      "reset a general setting to its default",
	"user.prefs.update":        "changed their display preferences",
	"admin.server.create":      "added server %s",
	"admin.server.update":      "changed server %s",
	"admin.server.pin":         "confirmed a fingerprint of server %s",
	"admin.server.credential":  "replaced a credential of server %s",
	"admin.server.enable":      "enabled server %s",
	"admin.server.disable":     "disabled server %s",
	"admin.server.delete":      "removed server %s",
	"admin.server.import":      "imported server %s from config.yaml",
	"admin.server.test":        "tested the connection to %s",
	"admin.server.fingerprint": "fetched a BMC fingerprint",
	"settings.shadowed":        "ignored the database copy of server %s (config.yaml defines it)",
	"server.maintenance.start": "started or scheduled maintenance of %s",
	"server.maintenance.end":   "ended maintenance of %s",
	"server.note.add":          "added a note to %s",
	"server.note.edit":         "edited a note of %s",
	"server.note.delete":       "deleted a note of %s",
	"server.note.pin":          "changed the pinned note of %s",
	"server.event.ack":         "acknowledged log entries of %s",
	"server.event.unack":       "removed an acknowledgement on %s",
	"server.notify.mute":       "muted notifications for %s",
	"server.notify.unmute":     "unmuted notifications for %s",
	"server.security.accept":   "accepted a security finding of %s as a risk",
	"server.security.unaccept": "ended the accepted risk of a security finding of %s",
	"server.security.rerun":    "re-ran the security checks of %s",
	"server.firmware.rescan":   "asked for a firmware re-scan of %s",
	"server.firmware.changed":  "recorded a firmware version change on %s",
}

// actionNames are short labels for authorization actions in refusals.
var actionNames = map[string]string{ //nolint:gosec // G101: action labels, not credentials
	"admin.users.manage": "manage users", "admin.tokens.manage": "manage API tokens", "admin.users": "view users",
	"admin.tokens": "view API tokens", "admin.audit.view": "view the audit log", "admin.audit.verify": "verify the audit chain",
	"console.vnc": "open the graphical console", "console.vnc.takeover": "take over the graphical console",
	"console.kvm_launch": "open the native BMC console", "admin.general.view": "view the general settings",
	"admin.general.manage": "change the general settings", "user.prefs": "change display preferences",
	"admin.servers.view": "view the servers", "admin.servers.manage": "change the servers",
	"server.maintenance": "change maintenance mode", "server.notes.write": "write server notes",
	"server.event.ack": "acknowledge log entries", "server.security.view": "view the security findings",
	"server.security.rerun": "re-run the security checks", "server.security.accept": "accept a security risk",
	"bmc.reset": "restart the BMC", "server.firmware.rescan": "re-scan the firmware", "server.firmware.view": "view the firmware",
	"server.firmware.export": "export the firmware list",
}

var classNames = map[string]string{
	"stepup_required": "step-up required", "forbidden": "role does not allow it", "csrf": "the form had expired",
	"rate_limited": "too many attempts", "unconfirmed": "not confirmed", "confirm_mismatch": "typed name did not match",
	"locked": "managed by config.yaml or locked", "conflict": "changed elsewhere first", "invalid": "invalid value",
	"lease_active": "a fan lease is active", "exists": "already exists", "cooldown": "ran moments ago",
	"paused": "polling is paused", "restarting": "the BMC is restarting", "power_pending": "a power action is being verified",
	"not_offered": "not offered by the BMC", "no_operator": "no operator BMC account", "privilege": "the operator account lacks the privilege",
	"unavailable": "not available for this server", "refused": "refused",
}

// auditSentence renders one audit record. names maps user IDs to usernames.
func auditSentence(rec store.AuditRecord, names map[string]string) string {
	who := principalName(rec.Principal)
	switch rec.Action {
	case "app.start":
		return "oob-manager started"
	case "app.stop":
		return "oob-manager stopped"
	}
	if rec.Action == "auth.login" && rec.Result != "ok" {
		return "Sign-in refused for " + who
	}
	if rec.Action == "auth.stepup" && rec.Result != "ok" {
		return "Step-up refused for " + who
	}
	verb, known := auditVerbs[rec.Action]
	if !known {
		if label, ok := actionNames[rec.Action]; ok && rec.Result == "denied" {
			return who + " was refused: " + label + reason(rec.ErrorClass)
		}
		return who + ": " + rec.Action
	}
	params := decodeParams(rec.ParamsJSON)
	s := who + " " + verb
	if strings.Contains(verb, "%s") {
		s = who + " " + fmt.Sprintf(verb, auditTarget(rec, params, names))
	}
	if after, ok := params["after"].(string); ok && rec.Action == "admin.user.role" {
		s += " to " + after
	}
	if ch := changeList(params); ch != "" {
		s += ": " + ch
	}
	if rec.Result == "denied" || rec.Result == "error" {
		s += " (" + rec.Result + reason(rec.ErrorClass) + ")"
	}
	return s
}

// changeList renders a settings change list ("changes": [{field, before, after}]) as
// "ui.time_zone UTC → America/New_York; …"; "" when there is none.
func changeList(params map[string]any) string {
	list, ok := params["changes"].([]any)
	if !ok {
		return ""
	}
	parts := make([]string, 0, len(list))
	for _, c := range list {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		parts = append(parts, fmt.Sprintf("%v %v → %v", m["field"], m["before"], m["after"]))
	}
	return strings.Join(parts, "; ")
}

func reason(class string) string {
	if class == "" {
		return ""
	}
	if n, ok := classNames[class]; ok {
		return " (" + n + ")"
	}
	return " (" + strings.ReplaceAll(class, "_", " ") + ")"
}

func principalName(p string) string {
	switch p {
	case "", "anonymous":
		return "an unknown user"
	case "cli":
		return "The command line"
	case "system":
		return "oob-manager"
	default:
		return p
	}
}

func auditTarget(rec store.AuditRecord, params map[string]any, names map[string]string) string {
	if id, ok := params["target_id"].(string); ok {
		if n, ok := names[id]; ok {
			return n
		}
		return "a deleted or unknown user"
	}
	for _, k := range []string{"target", "name", "username"} {
		if v, ok := params[k].(string); ok && v != "" {
			return strings.TrimPrefix(v, "server:")
		}
	}
	if rec.ServerID != "" {
		return rec.ServerID
	}
	return "an unnamed target"
}

func decodeParams(raw string) map[string]any {
	var m map[string]any
	if raw == "" || json.Unmarshal([]byte(raw), &m) != nil {
		return map[string]any{}
	}
	return m
}

// auditDetails is the parameter list, sorted by key; invalid JSON is shown raw.
func auditDetails(raw string) []kv {
	if raw == "" || raw == "{}" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return []kv{{"raw", raw}}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]kv, 0, len(keys))
	for _, k := range keys {
		if k == "changes" {
			continue // shown in the sentence (changeList)
		}
		out = append(out, kv{k, fmt.Sprint(m[k])})
	}
	return out
}

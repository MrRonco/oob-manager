package config

import (
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// NotificationsConfig is the `notifications:` section (tech_doc §26). Everything here
// is file-only: AllowedNetworks is the SSRF allowlist, so no browser session can widen
// it, and Targets are read-only in the browser (lock badge).
type NotificationsConfig struct {
	// AllowedNetworks lists CIDRs (or single IPs) that targets may reach although they
	// are private, and the only places plaintext (http, SMTP without TLS) may go.
	AllowedNetworks []string `yaml:"allowed_networks"`
	// Debounce is how long a changed health or PSU state must hold before it is sent
	// (default 90 s, at most 30 min; 0 takes the default).
	Debounce time.Duration      `yaml:"debounce"`
	Targets  []NotifyTargetFile `yaml:"targets"`
}

// NotifyTargetFile is one file-managed target. Secrets come from the age credential
// file entry SecretRef: ntfy, Gotify and webhook use its password as the token / HMAC
// key; Pushover uses username = user key and password = application token; email uses
// username and password for SMTP AUTH.
type NotifyTargetFile struct {
	ID                string          `yaml:"id"`
	Name              string          `yaml:"name"`
	Kind              string          `yaml:"kind"`
	URL               string          `yaml:"url"`
	SecretRef         string          `yaml:"secret_ref"`
	Enabled           *bool           `yaml:"enabled"`
	AllowPlaintext    bool            `yaml:"allow_plaintext"`
	IncludeDetail     bool            `yaml:"include_detail"`
	Classes           []string        `yaml:"classes"`
	MinSeverity       string          `yaml:"min_severity"`
	PushoverEmergency bool            `yaml:"pushover_emergency"`
	Email             NotifyEmailFile `yaml:"email"`
}

// NotifyEmailFile holds the email-only fields.
type NotifyEmailFile struct {
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`
	Security string   `yaml:"security"`
}

// Notification limits and enums (the notify package re-validates every target fully at
// startup; these are the structural checks that keep a typo from loading).
const (
	DefaultNotifyDebounce = 90 * time.Second
	MaxNotifyDebounce     = 30 * time.Minute
	defaultNotifySeverity = "warning"
)

var (
	notifyKinds      = []string{"ntfy", "pushover", "gotify", "webhook", "email"}
	notifyClasses    = []string{"health", "reachability", "sel", "psu", "fan", "power", "bmc", "console", "auth", "audit", "trust", "security", "firmware", "notify"}
	notifySeverities = []string{"info", "warning", "critical"}
	notifyIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

// NotifyClasses returns every subscribable event class name.
func NotifyClasses() []string { return slices.Clone(notifyClasses) }

// TargetEnabled reports the effective enabled flag (default true).
func (t NotifyTargetFile) TargetEnabled() bool { return t.Enabled == nil || *t.Enabled }

func notificationDefaults(n NotificationsConfig) NotificationsConfig {
	if n.Debounce == 0 {
		n.Debounce = DefaultNotifyDebounce
	}
	targets := make([]NotifyTargetFile, len(n.Targets))
	for i, t := range n.Targets {
		t.Classes = slices.Clone(t.Classes)
		t.Email.To = slices.Clone(t.Email.To)
		if len(t.Classes) == 0 {
			t.Classes = NotifyClasses()
		}
		if t.MinSeverity == "" {
			t.MinSeverity = defaultNotifySeverity
		}
		if t.Kind == "email" && t.Email.Security == "" {
			t.Email.Security = "starttls"
		}
		targets[i] = t
	}
	n.Targets = targets
	n.AllowedNetworks = slices.Clone(n.AllowedNetworks)
	return n
}

func validateNotifications(p problems, n NotificationsConfig) problems {
	for _, s := range n.AllowedNetworks {
		if !validNetwork(s) {
			p = p.add("notifications.allowed_networks: %q is not an IP address or CIDR", s)
		}
	}
	if n.Debounce < 0 || n.Debounce > MaxNotifyDebounce {
		p = p.add("notifications.debounce must be between 0 and %s", MaxNotifyDebounce)
	}
	seen := map[string]bool{}
	for i, t := range n.Targets {
		p = validateNotifyTarget(p, i, t)
		if seen[t.ID] {
			p = p.add("notifications.targets[%d]: duplicate id %q", i, t.ID)
		}
		seen[t.ID] = true
	}
	return p
}

func validateNotifyTarget(p problems, i int, t NotifyTargetFile) problems {
	at := func(f string) string { return "notifications.targets[" + strconv.Itoa(i) + "]." + f }
	if !notifyIDPattern.MatchString(t.ID) {
		p = p.add("%s must match %s", at("id"), notifyIDPattern)
	}
	if strings.TrimSpace(t.Name) == "" || len(t.Name) > 64 {
		p = p.add("%s must be 1-64 characters", at("name"))
	}
	if !slices.Contains(notifyKinds, t.Kind) {
		p = p.add("%s must be one of %s", at("kind"), strings.Join(notifyKinds, ", "))
	}
	if t.URL == "" {
		p = p.add("%s is required", at("url"))
	}
	if t.SecretRef != "" && !notifyIDPattern.MatchString(t.SecretRef) {
		p = p.add("%s must name an entry of the credential file", at("secret_ref"))
	}
	for _, c := range t.Classes {
		if !slices.Contains(notifyClasses, c) {
			p = p.add("%s: unknown class %q (one of %s)", at("classes"), c, strings.Join(notifyClasses, ", "))
		}
	}
	if !slices.Contains(notifySeverities, t.MinSeverity) {
		p = p.add("%s must be info, warning or critical", at("min_severity"))
	}
	return p
}

func validNetwork(s string) bool {
	if strings.Contains(s, "/") {
		pf, err := netip.ParsePrefix(s)
		return err == nil && pf.Addr().Zone() == ""
	}
	a, err := netip.ParseAddr(s)
	return err == nil && a.Zone() == ""
}

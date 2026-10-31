package config

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

const notifyYAML = `notifications:
  allowed_networks: [192.0.2.0/24, 198.51.100.7]
  debounce: 2m
  targets:
    - id: phone
      name: Phone
      kind: ntfy
      url: https://ntfy.example.net/oob
      secret_ref: ntfy-token
    - id: mail
      name: Ops mail
      kind: email
      url: smtp://192.0.2.25:587
      enabled: false
      classes: [health, power]
      min_severity: critical
      email: { from: oob@example.org, to: [ops@example.org] }
`

func TestNotificationsParseAndDefaults(t *testing.T) {
	cfg := mustParse(t, validYAML()+notifyYAML)
	n := cfg.Notifications
	if n.Debounce != 2*time.Minute || len(n.AllowedNetworks) != 2 || len(n.Targets) != 2 {
		t.Fatalf("notifications = %+v", n)
	}
	phone, mail := n.Targets[0], n.Targets[1]
	if !phone.TargetEnabled() || phone.MinSeverity != "warning" || !slices.Equal(phone.Classes, NotifyClasses()) {
		t.Fatalf("phone defaults = %+v", phone)
	}
	if mail.TargetEnabled() || mail.Email.Security != "starttls" || mail.MinSeverity != "critical" {
		t.Fatalf("mail = %+v", mail)
	}
	if d := mustParse(t, validYAML()).Notifications.Debounce; d != DefaultNotifyDebounce {
		t.Fatalf("default debounce %v", d)
	}
}

func TestNotificationsRejects(t *testing.T) {
	tests := []struct{ name, from, to, want string }{
		{"network", "198.51.100.7]", "not-a-net]", "allowed_networks"},
		{"debounce", "debounce: 2m", "debounce: 31m", "notifications.debounce"},
		{"id", "id: phone", "id: Phone!", "targets[0].id"},
		{"kind", "kind: ntfy", "kind: slack", "targets[0].kind"},
		{"url", "url: https://ntfy.example.net/oob", "url: ''", "targets[0].url"},
		{"ref", "secret_ref: ntfy-token", "secret_ref: '../x'", "secret_ref"},
		{"class", "classes: [health, power]", "classes: [health, bogus]", "unknown class"},
		{"severity", "min_severity: critical", "min_severity: panic", "min_severity"},
		{"duplicate", "id: mail", "id: phone", "duplicate id"},
		{"name", "name: Phone", "name: ''", "targets[0].name"},
	}
	for _, tc := range tests {
		src := validYAML() + strings.Replace(notifyYAML, tc.from, tc.to, 1)
		_, err := Parse([]byte(src))
		var ve *ValidationError
		if !errors.As(err, &ve) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

package notify

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateRejects(t *testing.T) {
	ok := Target{ID: "ok", Name: "OK", Kind: KindNtfy, URL: "https://ntfy.example.net/topic", Enabled: true,
		Classes: []Class{ClassHealth}, MinSeverity: SeverityWarning}
	if err := Validate(ok, Secrets{}); err != nil {
		t.Fatal(err)
	}
	mail := emailTarget("smtp://mail.example.net:587", EmailSTARTTLS)
	cases := map[string]struct {
		t Target
		s Secrets
	}{
		"bad id":             {mod(ok, func(t *Target) { t.ID = "Bad ID" }), Secrets{}},
		"empty name":         {mod(ok, func(t *Target) { t.Name = "" }), Secrets{}},
		"control in name":    {mod(ok, func(t *Target) { t.Name = "a\x07" }), Secrets{}},
		"kind":               {mod(ok, func(t *Target) { t.Kind = "slack" }), Secrets{}},
		"no scheme":          {mod(ok, func(t *Target) { t.URL = "ntfy.example.net/x" }), Secrets{}},
		"ftp":                {mod(ok, func(t *Target) { t.URL = "ftp://example.net/x" }), Secrets{}},
		"userinfo":           {mod(ok, func(t *Target) { t.URL = "https://u:p@example.net/x" }), Secrets{}},
		"fragment":           {mod(ok, func(t *Target) { t.URL = "https://example.net/x#y" }), Secrets{}},
		"space":              {mod(ok, func(t *Target) { t.URL = "https://example.net/a b" }), Secrets{}},
		"port":               {mod(ok, func(t *Target) { t.URL = "https://example.net:99999/x" }), Secrets{}},
		"long url":           {mod(ok, func(t *Target) { t.URL = "https://example.net/" + strings.Repeat("a", 600) }), Secrets{}},
		"class":              {mod(ok, func(t *Target) { t.Classes = []Class{"bogus"} }), Secrets{}},
		"severity":           {mod(ok, func(t *Target) { t.MinSeverity = 9 }), Secrets{}},
		"emergency not po":   {mod(ok, func(t *Target) { t.PushoverEmergency = true }), Secrets{}},
		"pushover no user":   {mod(ok, func(t *Target) { t.Kind = KindPushover }), sec("t", "", "")},
		"gotify no token":    {mod(ok, func(t *Target) { t.Kind = KindGotify }), Secrets{}},
		"secret newline":     {ok, sec("a\nb", "", "")},
		"secret long":        {ok, sec(strings.Repeat("x", 600), "", "")},
		"smtp scheme":        {mod(mail, func(t *Target) { t.URL = "https://mail.example.net:587" }), Secrets{}},
		"smtp no port":       {mod(mail, func(t *Target) { t.URL = "smtp://mail.example.net" }), Secrets{}},
		"smtp path":          {mod(mail, func(t *Target) { t.URL = "smtp://mail.example.net:25/x" }), Secrets{}},
		"smtp security":      {mod(mail, func(t *Target) { t.EmailSecurity = "ssl3" }), Secrets{}},
		"from display":       {mod(mail, func(t *Target) { t.EmailFrom = "OOB <oob@example.org>" }), Secrets{}},
		"no recipients":      {mod(mail, func(t *Target) { t.EmailTo = nil }), Secrets{}},
		"too many rcpt":      {mod(mail, func(t *Target) { t.EmailTo = make([]string, 11) }), Secrets{}},
		"bad rcpt":           {mod(mail, func(t *Target) { t.EmailTo = []string{"nope"} }), Secrets{}},
		"half auth":          {mail, sec("", "user", "")},
		"plaintext no optin": {mod(mail, func(t *Target) { t.EmailSecurity = EmailNone }), Secrets{}},
	}
	for name, c := range cases {
		if err := Validate(c.t, c.s); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func mod(t Target, f func(*Target)) Target {
	t = t.clone()
	f(&t)
	return t
}

func TestEnumsAndLabels(t *testing.T) {
	for _, k := range Kinds() {
		if got, err := ParseKind(string(k)); err != nil || got != k || k.Label() == "" {
			t.Errorf("kind %s", k)
		}
	}
	for _, c := range append(Classes(), ClassTest) {
		if c.Label() == "" || c.Label() == string(c) {
			t.Errorf("class %s has no label", c)
		}
	}
	if _, err := ParseClass(string(ClassTest)); err == nil {
		t.Error("test class is subscribable")
	}
	for _, s := range Severities() {
		if got, err := ParseSeverity(s.String()); err != nil || got != s {
			t.Errorf("severity %v", s)
		}
	}
	if _, err := ParseSeverity("panic"); err == nil || Severity(0).String() != "unknown" || Kind("x").Label() != "x" {
		t.Error("unknown values")
	}
	if Class("x").Label() != "x" || ClassPower.Mutable() || !ClassSEL.Mutable() {
		t.Error("class properties")
	}
	if (Target{URL: "://bad"}).Host() != "" {
		t.Error("host of a bad URL")
	}
}

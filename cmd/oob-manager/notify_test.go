package main

import (
	"testing"

	"oob-manager/internal/audit"
	"oob-manager/internal/config"
	"oob-manager/internal/notify"
	"oob-manager/internal/secrets"
)

func TestFileTargetsReadSecretsPerKind(t *testing.T) {
	creds, err := secrets.ParseCredentials([]byte("po: {username: user-key, password: app-token}\n" +
		"hook: {password: hmac}\nmail: {username: mailer, password: pw}\nmailnone: {password: x}\n"))
	if err != nil {
		t.Fatal(err)
	}
	on := false
	list := []config.NotifyTargetFile{
		{ID: "po", Name: "PO", Kind: "pushover", URL: notify.DefaultPushoverURL, SecretRef: "po", MinSeverity: "warning",
			Classes: []string{"health"}},
		{ID: "hook", Name: "Hook", Kind: "webhook", URL: "https://hooks.example.net/x", SecretRef: "hook", MinSeverity: "info",
			Enabled: &on},
		{ID: "mail", Name: "Mail", Kind: "email", URL: "smtp://192.0.2.25:587", SecretRef: "mail", MinSeverity: "critical",
			Email: config.NotifyEmailFile{From: "a@example.org", To: []string{"b@example.org"}, Security: "starttls"}},
		{ID: "mail2", Name: "Mail2", Kind: "email", URL: "smtp://192.0.2.25:587", SecretRef: "mailnone", MinSeverity: "info"},
	}
	got, err := fileTargets(list, creds)
	if err != nil || len(got) != 4 {
		t.Fatalf("fileTargets: %v %d", err, len(got))
	}
	if got[0].Secrets.Token.Reveal() != "app-token" || got[0].Secrets.User.Reveal() != "user-key" ||
		got[0].Target.MinSeverity != notify.SeverityWarning || len(got[0].Target.Classes) != 1 {
		t.Errorf("pushover: %+v", got[0].Target)
	}
	if got[1].Secrets.Token.Reveal() != "hmac" || got[1].Target.Enabled {
		t.Errorf("webhook: %+v", got[1].Target)
	}
	if got[2].Secrets.User.Reveal() != "mailer" || got[2].Secrets.Password.Reveal() != "pw" || got[2].Target.EmailTo[0] != "b@example.org" {
		t.Errorf("email: %+v", got[2].Target)
	}
	if !got[3].Secrets.IsZero() {
		t.Error("email without a username must not authenticate")
	}
	for _, bad := range []config.NotifyTargetFile{
		{ID: "x", Kind: "slack", MinSeverity: "info"},
		{ID: "x", Kind: "ntfy", MinSeverity: "loud"},
		{ID: "x", Kind: "ntfy", MinSeverity: "info", Classes: []string{"bogus"}},
		{ID: "x", Kind: "ntfy", MinSeverity: "info", SecretRef: "missing"},
	} {
		if _, err := fileTargets([]config.NotifyTargetFile{bad}, creds); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

type countSink struct{ n int }

func (c *countSink) Enqueue(audit.Message) bool { c.n++; return true }

func TestTeeAndLateTap(t *testing.T) {
	late := &lateTap{}
	if teeSink(nil, late) != audit.Sink(late) {
		t.Fatal("without GELF the tap is the sink")
	}
	gelf := &countSink{}
	sink := teeSink(gelf, late)
	if !sink.Enqueue(audit.Message{}) || gelf.n != 1 {
		t.Fatal("tee did not forward before the tap exists")
	}
	var got []notify.Event
	late.p.Store(notify.NewTap(func(e notify.Event) { got = append(got, e) }, nil, nil))
	sink.Enqueue(audit.Message{Fields: map[string]any{"action": "admin.audit.verify", "result": "error",
		"error_class": "tampered", "principal": "a"}})
	if gelf.n != 2 || len(got) != 1 || got[0].Class != notify.ClassAudit {
		t.Fatalf("gelf %d, events %+v", gelf.n, got)
	}
	if uiNotifications(nil) != nil {
		t.Fatal("nil service must be a nil interface")
	}
	if _, err := notify.ParseNetworks([]string{"bad"}); err == nil {
		t.Fatal("bad network parsed")
	}
}

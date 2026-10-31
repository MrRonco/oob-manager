package notify

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"
)

func emailTarget(url string, security EmailSecurity) Target {
	return Target{ID: "mail", Name: "Ops mail", Kind: KindEmail, URL: url, Enabled: true, Classes: allClasses(),
		MinSeverity: SeverityInfo, EmailFrom: "oob@example.org", EmailTo: []string{"ops@example.org", "oncall@example.org"},
		EmailSecurity: security}
}

func sendMail(t *testing.T, f *fakeSMTP, tg Target, s Secrets) error {
	t.Helper()
	d := NewDispatcher(DispatchConfig{Transport: f.transport(), Logger: quiet(), Attempts: 1,
		Now: func() time.Time { return fixedNow }})
	return d.SendNow(context.Background(), tg, s, testEvent())
}

var volatileHeader = regexp.MustCompile(`(?m)^Message-ID: <[0-9a-f]+@`)

func TestEmailSTARTTLSWithAuthGolden(t *testing.T) {
	f := newFakeSMTP(t, false, true, true)
	tg := emailTarget(f.url(), EmailSTARTTLS)
	if err := sendMail(t, f, tg, sec("", "mailer", "smtp-pass")); err != nil {
		t.Fatalf("send: %v (%s)", err, ErrorClass(err))
	}
	msgs, auths, sawTLS := f.snapshot()
	if !sawTLS || len(msgs) != 1 || len(auths) != 1 || auths[0] != "|mailer|smtp-pass" {
		t.Fatalf("tls %v, %d messages, auth %v", sawTLS, len(msgs), auths)
	}
	golden(t, "email.txt", []byte(volatileHeader.ReplaceAllString(msgs[0], "Message-ID: <ID@")))
}

func TestEmailImplicitTLS(t *testing.T) {
	f := newFakeSMTP(t, true, false, true)
	if err := sendMail(t, f, emailTarget(f.url(), EmailTLS), sec("", "mailer", "smtp-pass")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if msgs, _, sawTLS := f.snapshot(); !sawTLS || len(msgs) != 1 {
		t.Fatal("implicit TLS message not delivered")
	}
}

func TestEmailRefusesMissingSTARTTLS(t *testing.T) {
	f := newFakeSMTP(t, false, false, true)
	err := sendMail(t, f, emailTarget(f.url(), EmailSTARTTLS), sec("", "mailer", "smtp-pass"))
	msgs, auths, _ := f.snapshot()
	if ErrorClass(err) != classTLS || len(msgs) != 0 || len(auths) != 0 {
		t.Fatalf("downgraded: class %q, %d messages, auth %v", ErrorClass(err), len(msgs), auths)
	}
}

func TestEmailPlaintextLANWithoutAuth(t *testing.T) {
	f := newFakeSMTP(t, false, false, false)
	tg := emailTarget(f.url(), EmailNone)
	tg.AllowPlaintext = true
	if err := Validate(tg, sec("", "mailer", "pw")); err == nil {
		t.Fatal("plaintext SMTP with a password validated")
	}
	if err := Validate(tg, Secrets{}); err != nil {
		t.Fatal(err)
	}
	if err := sendMail(t, f, tg, Secrets{}); err != nil {
		t.Fatalf("plaintext LAN relay: %v", err)
	}
	tg.AllowPlaintext = false
	if err := Validate(tg, Secrets{}); err == nil {
		t.Fatal("plaintext SMTP without the LAN opt-in validated")
	}
	tr := f.transport()
	tr.Policy.Allowed = nil
	d := NewDispatcher(DispatchConfig{Transport: tr, Logger: quiet(), Attempts: 1})
	tg.AllowPlaintext = true
	if err := d.SendNow(context.Background(), tg, Secrets{}, testEvent()); ErrorClass(err) != classBlocked {
		t.Fatalf("plaintext SMTP outside allowed_networks: %v", err)
	}
}

func TestEmailReplyClasses(t *testing.T) {
	for code, retry := range map[string]bool{"451": true, "550": false} {
		f := newFakeSMTP(t, false, true, false)
		f.rcptCode = code
		err := sendMail(t, f, emailTarget(f.url(), EmailSTARTTLS), Secrets{})
		if ErrorClass(err) != classSMTP || retryable(err) != retry || strings.Contains(err.Error(), "rcpt") {
			t.Errorf("%s: class %q retry %v err %v", code, ErrorClass(err), retryable(err), err)
		}
	}
}

func TestEmailHeadersCannotBeInjected(t *testing.T) {
	e := testEvent()
	e.Title = "x\r\nBcc: victim@example.org"
	msg, err := buildEmail(emailTarget("smtp://192.0.2.1:587", EmailSTARTTLS), e, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	head, _, _ := strings.Cut(string(msg), "\r\n\r\n")
	if strings.Contains(head, "\r\nBcc:") {
		t.Fatalf("header injected:\n%s", head)
	}
	if err := checkAddress("a@example.org\r\nBcc: b@example.org"); err == nil {
		t.Fatal("address with CRLF accepted")
	}
}

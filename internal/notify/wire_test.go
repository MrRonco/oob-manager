package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func dispatcherFor(r *receiver) *Dispatcher {
	return NewDispatcher(DispatchConfig{Transport: transportFor(r), Instance: "Lab OOB", Now: func() time.Time { return fixedNow },
		Logger: quiet(), Attempts: 1})
}

func sendOnce(t *testing.T, r *receiver, tg Target, s Secrets, e Event) captured {
	t.Helper()
	if err := dispatcherFor(r).SendNow(context.Background(), tg, s, e); err != nil {
		t.Fatalf("send: %v (%s)", err, ErrorClass(err))
	}
	reqs := r.requests()
	if len(reqs) != 1 {
		t.Fatalf("receiver saw %d requests", len(reqs))
	}
	return reqs[0]
}

func target(kind Kind, url string) Target {
	return Target{ID: "t1", Name: "Phone", Kind: kind, URL: url, Enabled: true, Classes: allClasses(),
		MinSeverity: SeverityInfo, IncludeDetail: true}
}

func TestNtfyWireFormat(t *testing.T) {
	r := newReceiver(t, true)
	c := sendOnce(t, r, target(KindNtfy, r.srv.URL+"/oob-alerts"), sec("tk_example", "", ""), testEvent())
	golden(t, "ntfy.txt", wire(c, "Authorization", "Content-Type", "Priority", "Tags", "Title", "User-Agent"))
}

func TestNtfyWithoutDetailOrToken(t *testing.T) {
	r := newReceiver(t, true)
	tg := target(KindNtfy, r.srv.URL+"/oob-alerts")
	tg.IncludeDetail = false
	c := sendOnce(t, r, tg, Secrets{}, testEvent())
	if strings.Contains(string(c.Body), "power input") || c.Header.Get("Authorization") != "" {
		t.Fatalf("detail or auth leaked: %q %q", c.Body, c.Header.Get("Authorization"))
	}
}

func TestPushoverWireFormat(t *testing.T) {
	r := newReceiver(t, true)
	c := sendOnce(t, r, target(KindPushover, r.srv.URL+"/1/messages.json"), sec("app-token", "user-key", ""), testEvent())
	golden(t, "pushover.txt", wire(c, "Content-Type", "User-Agent"))
}

func TestPushoverEmergencyOptIn(t *testing.T) {
	r := newReceiver(t, true)
	tg := target(KindPushover, r.srv.URL+"/1/messages.json")
	tg.PushoverEmergency = true
	c := sendOnce(t, r, tg, sec("app-token", "user-key", ""), testEvent())
	golden(t, "pushover-emergency.txt", wire(c, "Content-Type"))
}

func TestGotifyWireFormat(t *testing.T) {
	r := newReceiver(t, true)
	c := sendOnce(t, r, target(KindGotify, r.srv.URL+"/gotify/"), sec("gotify-app-token", "", ""), testEvent())
	golden(t, "gotify.txt", wire(c, "Content-Type", "X-Gotify-Key", "User-Agent"))
}

func TestWebhookWireFormatAndSignature(t *testing.T) {
	r := newReceiver(t, true)
	c := sendOnce(t, r, target(KindWebhook, r.srv.URL+"/hooks/oob?src=lab"), sec("hmac-secret", "", ""), testEvent())
	golden(t, "webhook.txt", wire(c, "Content-Type", HeaderEvent, HeaderDelivery, HeaderTimestamp, HeaderSignature))
	want := Sign([]byte("hmac-secret"), c.Header.Get(HeaderTimestamp), c.Body)
	if c.Header.Get(HeaderSignature) != want {
		t.Fatalf("signature %q, want %q", c.Header.Get(HeaderSignature), want)
	}
	var p WebhookPayload
	if err := json.Unmarshal(c.Body, &p); err != nil || p.Version != WebhookVersion || p.Server.ID != "srv-a" {
		t.Fatalf("payload: %v %+v", err, p)
	}
}

func TestWebhookUnsignedWithoutSecret(t *testing.T) {
	r := newReceiver(t, true)
	tg := target(KindWebhook, r.srv.URL+"/hook")
	e := testEvent()
	e.ServerID, e.ServerName = "", ""
	c := sendOnce(t, r, tg, Secrets{}, e)
	if c.Header.Get(HeaderSignature) != "" || strings.Contains(string(c.Body), `"server"`) {
		t.Fatalf("unexpected signature or server: %s", c.Body)
	}
}

func TestPriorityMapping(t *testing.T) {
	base := testEvent()
	cases := []struct {
		sev                        Severity
		recovery                   bool
		ntfy, pushover, pushEm, gt int
	}{
		{SeverityInfo, false, 3, -1, -1, 2},
		{SeverityWarning, false, 4, 0, 0, 5},
		{SeverityCritical, false, 5, 1, 2, 8},
		{SeverityCritical, true, 3, 0, 0, 2},
	}
	for _, c := range cases {
		e := base
		e.Severity, e.Recovery = c.sev, c.recovery
		em := Target{PushoverEmergency: true}
		if got := ntfyPriority(e); got != c.ntfy {
			t.Errorf("ntfy %v/%v = %d", c.sev, c.recovery, got)
		}
		if got := pushoverPriority(Target{}, e); got != c.pushover {
			t.Errorf("pushover %v/%v = %d", c.sev, c.recovery, got)
		}
		if got := pushoverPriority(em, e); got != c.pushEm {
			t.Errorf("pushover emergency %v/%v = %d", c.sev, c.recovery, got)
		}
		if got := gotifyPriority(e); got != c.gt {
			t.Errorf("gotify %v/%v = %d", c.sev, c.recovery, got)
		}
	}
	test := base
	test.Class = ClassTest
	if ntfyPriority(test) != 3 || pushoverPriority(Target{PushoverEmergency: true}, test) != 0 || gotifyPriority(test) != 2 {
		t.Error("test events must use the default priority")
	}
}

func TestReceiverStatusClasses(t *testing.T) {
	cases := map[int]string{http.StatusFound: classRedirect, http.StatusUnauthorized: classHTTP4xx,
		http.StatusTooManyRequests: classRateLimited, http.StatusBadGateway: classHTTP5xx}
	for code, want := range cases {
		r := newReceiver(t, true, code)
		err := dispatcherFor(r).SendNow(context.Background(), target(KindNtfy, r.srv.URL+"/x"), Secrets{}, testEvent())
		if ErrorClass(err) != want {
			t.Errorf("%d: class %q, want %q", code, ErrorClass(err), want)
		}
		if err != nil && strings.Contains(err.Error(), "receiver text") {
			t.Errorf("%d: receiver text in the error", code)
		}
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	inner := newReceiver(t, true)
	r := newReceiver(t, true)
	r.hook = func(w http.ResponseWriter) bool {
		w.Header().Set("Location", inner.srv.URL+"/stolen")
		w.WriteHeader(http.StatusTemporaryRedirect)
		return true
	}
	err := dispatcherFor(r).SendNow(context.Background(), target(KindNtfy, r.srv.URL+"/x"), sec("tk", "", ""), testEvent())
	if ErrorClass(err) != classRedirect || inner.count() != 0 {
		t.Fatalf("redirect followed: class %q, inner saw %d", ErrorClass(err), inner.count())
	}
}

func TestResponseBodyIsCapped(t *testing.T) {
	r := newReceiver(t, true)
	r.hook = func(w http.ResponseWriter) bool {
		w.WriteHeader(http.StatusOK)
		chunk := []byte(strings.Repeat("x", 1<<10))
		for range 4096 { // 4 MiB: the client must stop reading long before
			if _, err := w.Write(chunk); err != nil {
				return true
			}
		}
		return true
	}
	if err := dispatcherFor(r).SendNow(context.Background(), target(KindNtfy, r.srv.URL+"/x"), Secrets{}, testEvent()); err != nil {
		t.Fatalf("capped read failed: %v", err)
	}
}

func TestBodyStripsControlCharacters(t *testing.T) {
	e := testEvent()
	e.Detail = []string{"line\r\nInjected: header\x1b[31m"}
	b := body(e)
	if strings.ContainsAny(b[len(e.Message):], "\r\x1b") || strings.Count(b, "\n") != 2 {
		t.Fatalf("control characters kept: %q", b)
	}
	if got := clip(strings.Repeat("é", 10), 7); !utf8.ValidString(got) || len(got) > 7 {
		t.Fatalf("clip: %q", got)
	}
}

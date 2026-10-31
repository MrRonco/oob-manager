package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// WebhookVersion is the version of the documented webhook JSON body
// (deploy/README.md "Notifications"). Fields are only ever added within a version.
const WebhookVersion = "1"

// Webhook headers.
const (
	HeaderEvent     = "X-OOB-Event"
	HeaderDelivery  = "X-OOB-Delivery"
	HeaderTimestamp = "X-OOB-Timestamp"
	HeaderSignature = "X-OOB-Signature"
)

// Field caps of the push services (Pushover: title 250, message 1024).
const (
	maxTitle   = 250
	maxMessage = 1024
)

// body is the human text: the message, then up to five detail lines when included.
func body(e Event) string {
	var b strings.Builder
	b.WriteString(e.Message)
	if len(e.Detail) > 0 {
		b.WriteString("\n")
		for _, d := range e.Detail {
			b.WriteString("\n• " + oneLine(d))
		}
	}
	return b.String()
}

// oneLine removes control characters so BMC text cannot add header lines or fake
// message structure.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n - len("…")
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// ntfyPriority maps to ntfy's 1-5 scale (3 = default).
func ntfyPriority(e Event) int {
	if e.quiet() {
		return 3
	}
	switch e.Severity {
	case SeverityCritical:
		return 5
	case SeverityWarning:
		return 4
	default:
		return 3
	}
}

func ntfyTags(e Event) string {
	switch {
	case e.Class == ClassMaintenance:
		return "wrench"
	case e.Recovery:
		return "white_check_mark"
	case e.Class == ClassTest:
		return "test_tube"
	case e.Severity == SeverityCritical:
		return "rotating_light"
	case e.Severity == SeverityWarning:
		return "warning"
	default:
		return "information_source"
	}
}

func buildNtfy(ctx context.Context, t Target, sec Secrets, e Event) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, strings.NewReader(clip(body(e), 4096)))
	if err != nil {
		return nil, failed(classBlocked, false, "notify: bad URL")
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("Title", clip(oneLine(e.Title), maxTitle))
	req.Header.Set("Priority", strconv.Itoa(ntfyPriority(e)))
	req.Header.Set("Tags", ntfyTags(e))
	if !sec.Token.IsZero() {
		req.Header.Set("Authorization", "Bearer "+sec.Token.Reveal())
	}
	return req, nil
}

// pushoverPriority: -1 quiet for info and recoveries, 0 normal for warnings, 1 high for
// critical; 2 (emergency, repeats until acknowledged) only when the target opted in.
func pushoverPriority(t Target, e Event) int {
	if e.quiet() {
		return 0
	}
	switch e.Severity {
	case SeverityCritical:
		if t.PushoverEmergency {
			return 2
		}
		return 1
	case SeverityWarning:
		return 0
	default:
		return -1
	}
}

func buildPushover(ctx context.Context, t Target, sec Secrets, e Event) (*http.Request, error) {
	prio := pushoverPriority(t, e)
	form := url.Values{
		"token":     {sec.Token.Reveal()},
		"user":      {sec.User.Reveal()},
		"title":     {clip(oneLine(e.Title), maxTitle)},
		"message":   {clip(body(e), maxMessage)},
		"priority":  {strconv.Itoa(prio)},
		"timestamp": {strconv.FormatInt(e.At.Unix(), 10)},
	}
	if prio == 2 {
		form.Set("retry", "300")
		form.Set("expire", "3600")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, failed(classBlocked, false, "notify: bad URL")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// gotifyPriority uses Gotify's 0-10 scale (clients alert from 4 and up, 8+ is high).
func gotifyPriority(e Event) int {
	if e.quiet() {
		return 2
	}
	switch e.Severity {
	case SeverityCritical:
		return 8
	case SeverityWarning:
		return 5
	default:
		return 2
	}
}

func buildGotify(ctx context.Context, t Target, sec Secrets, e Event) (*http.Request, error) {
	u, err := url.Parse(t.URL)
	if err != nil {
		return nil, failed(classBlocked, false, "notify: bad URL")
	}
	u = u.JoinPath("message")
	payload, err := json.Marshal(map[string]any{"title": clip(oneLine(e.Title), maxTitle), "message": body(e),
		"priority": gotifyPriority(e)})
	if err != nil {
		return nil, fmt.Errorf("notify: gotify: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, failed(classBlocked, false, "notify: bad URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gotify-Key", sec.Token.Reveal())
	return req, nil
}

// WebhookPayload is the documented webhook body, version 1.
type WebhookPayload struct {
	Version  string         `json:"version"`
	ID       string         `json:"id"`
	Time     string         `json:"time"`
	Instance string         `json:"instance,omitempty"`
	Class    Class          `json:"class"`
	Severity string         `json:"severity"`
	Recovery bool           `json:"recovery"`
	Server   *WebhookServer `json:"server,omitempty"`
	Title    string         `json:"title"`
	Message  string         `json:"message"`
	Count    int            `json:"count,omitempty"`
	Detail   []string       `json:"detail,omitempty"`
}

// WebhookServer identifies the server an event is about.
type WebhookServer struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func webhookPayload(instance string, e Event) WebhookPayload {
	p := WebhookPayload{Version: WebhookVersion, ID: e.ID, Time: e.At.UTC().Format(time.RFC3339), Instance: instance,
		Class: e.Class, Severity: e.Severity.String(), Recovery: e.Recovery, Title: e.Title, Message: e.Message,
		Count: e.Count}
	if e.ServerID != "" {
		p.Server = &WebhookServer{ID: e.ServerID, Name: e.ServerName}
	}
	for _, d := range e.Detail {
		p.Detail = append(p.Detail, oneLine(d))
	}
	return p
}

// Sign is the webhook signature: hex HMAC-SHA256 over "<timestamp>.<body>" with the
// target's secret, sent as "sha256=<hex>". Receivers recompute it and reject old
// timestamps (replay).
func Sign(secret []byte, timestamp string, payload []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(timestamp + "."))
	m.Write(payload)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func buildWebhook(ctx context.Context, t Target, sec Secrets, e Event, instance string, now time.Time) (*http.Request, error) {
	payload, err := json.Marshal(webhookPayload(instance, e))
	if err != nil {
		return nil, fmt.Errorf("notify: webhook: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(payload))
	if err != nil {
		return nil, failed(classBlocked, false, "notify: bad URL")
	}
	ts := strconv.FormatInt(now.Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderEvent, string(e.Class))
	req.Header.Set(HeaderDelivery, e.ID)
	req.Header.Set(HeaderTimestamp, ts)
	if !sec.Token.IsZero() {
		key := sec.Token.Bytes()
		req.Header.Set(HeaderSignature, Sign(key, ts, payload))
		wipe(key)
	}
	return req, nil
}

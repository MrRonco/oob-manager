package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/config"
	"oob-manager/internal/fleet"
	"oob-manager/internal/maint"
	"oob-manager/internal/notify"
	"oob-manager/internal/secrets"
)

// lateTap forwards audit records to the notifications tap once serve has built it
// (the audit logger exists before the notifications service). Enqueue never blocks.
type lateTap struct {
	p   atomic.Pointer[notify.Tap]
	svc atomic.Pointer[notify.Service] // for events that do not come from the audit trail
}

// Enqueue implements audit.Sink.
func (l *lateTap) Enqueue(m audit.Message) bool {
	if t := l.p.Load(); t != nil {
		t.Enqueue(m)
	}
	return true
}

// tee sends each audit message to every sink (GELF, notifications).
type tee []audit.Sink

func (t tee) Enqueue(m audit.Message) bool {
	ok := true
	for _, s := range t {
		ok = s.Enqueue(m) && ok
	}
	return ok
}

// teeSink combines the GELF shipper (nil when off) with the notifications tap.
func teeSink(gelf audit.Sink, tap *lateTap) audit.Sink {
	if gelf == nil {
		return tap
	}
	return tee{gelf, tap}
}

// buildNotify builds the notifications service: file targets with their secrets from
// the age credential file, browser targets from the database (sealed with the
// app-keys derived key), the SSRF policy from notifications.allowed_networks, and the
// audit tap. It never contacts a receiver.
func buildNotify(ctx context.Context, cfg config.Config, c *core, creds secrets.Credentials, fl fleet.Reader,
	sup notify.Suppressor, log *slog.Logger) (*notify.Service, error) {
	allowed, err := notify.ParseNetworks(cfg.Notifications.AllowedNetworks)
	if err != nil {
		return nil, err
	}
	file, err := fileTargets(cfg.Notifications.Targets, creds)
	if err != nil {
		return nil, err
	}
	sealer, err := notify.NewSealer(c.notifyKey)
	if err != nil {
		return nil, err
	}
	var instance func() string // the live Settings → General value, when wired
	if c.settings != nil {
		instance = func() string { return c.settings.Current().General.InstanceName }
	}
	svc, err := notify.New(ctx, notify.Config{DB: c.db, Audit: c.audit, Sealer: sealer, File: file,
		Locked: cfg.Locked(config.SectionIntegrations), Fleet: fl, Suppress: sup, Debounce: cfg.Notifications.Debounce, Logger: log,
		Dispatch: notify.DispatchConfig{Transport: notify.Transport{Policy: notify.Policy{Allowed: allowed}},
			Instance: cfg.UI.InstanceName, InstanceFn: instance}})
	if err != nil {
		return nil, err
	}
	name := func(id string) string {
		if s, ok := fl.Server(id); ok {
			return s.Name
		}
		return id
	}
	c.notifyTap.p.Store(notify.NewTap(svc.Emit, name, nil))
	c.notifyTap.svc.Store(svc)
	if c.chainBroken {
		svc.Emit(notify.AuditChainEvent("found by the startup verification", time.Now()))
	}
	return svc, nil
}

// fileTargets converts config.yaml targets, reading each secret_ref from the credential
// file: ntfy, Gotify and webhook use the entry's password as token / HMAC key; Pushover
// username = user key and password = application token; email username/password = SMTP AUTH.
func fileTargets(list []config.NotifyTargetFile, creds secrets.Credentials) ([]notify.FileTarget, error) {
	out := make([]notify.FileTarget, 0, len(list))
	for _, f := range list {
		t, err := fileTarget(f)
		if err != nil {
			return nil, err
		}
		var sec notify.Secrets
		if f.SecretRef != "" {
			cred, err := creds.Lookup(f.SecretRef)
			if err != nil {
				return nil, fmt.Errorf("notifications target %s: %w", f.ID, err)
			}
			sec = secretsFor(t.Kind, cred)
		}
		out = append(out, notify.FileTarget{Target: t, Secrets: sec})
	}
	return out, nil
}

func fileTarget(f config.NotifyTargetFile) (notify.Target, error) {
	kind, err := notify.ParseKind(f.Kind)
	if err != nil {
		return notify.Target{}, err
	}
	sev, err := notify.ParseSeverity(f.MinSeverity)
	if err != nil {
		return notify.Target{}, err
	}
	t := notify.Target{ID: f.ID, Name: f.Name, Kind: kind, URL: f.URL, Enabled: f.TargetEnabled(),
		AllowPlaintext: f.AllowPlaintext, IncludeDetail: f.IncludeDetail, MinSeverity: sev,
		PushoverEmergency: f.PushoverEmergency, EmailFrom: f.Email.From, EmailTo: f.Email.To,
		EmailSecurity: notify.EmailSecurity(f.Email.Security)}
	for _, c := range f.Classes {
		cl, err := notify.ParseClass(c)
		if err != nil {
			return notify.Target{}, err
		}
		t.Classes = append(t.Classes, cl)
	}
	return t, nil
}

func secretsFor(k notify.Kind, cred secrets.Credential) notify.Secrets {
	switch k {
	case notify.KindPushover:
		return notify.Secrets{Token: cred.Password, User: secrets.New(cred.Username)}
	case notify.KindEmail:
		if cred.Username == "" {
			return notify.Secrets{}
		}
		return notify.Secrets{User: secrets.New(cred.Username), Password: cred.Password}
	default:
		return notify.Secrets{Token: cred.Password}
	}
}

// Trust forwards a pinned-key check outcome (S3 Test connection) to the tap; a no-op
// until the notifications service exists.
func (l *lateTap) Trust(serverID, what string, ok bool) {
	if l == nil {
		return
	}
	if t := l.p.Load(); t != nil {
		t.Trust(serverID, what, ok)
	}
}

// keep forgets the trust state of servers that are gone (see notify.Tap.Keep).
func (l *lateTap) keep(ids []string) {
	if l == nil {
		return
	}
	if t := l.p.Load(); t != nil {
		t.Keep(ids)
	}
}

// attachNotify builds maintenance mode (tech_doc §28) and the notifications over the
// runtime's fleet, with maintenance as their Suppressor, and connects maintenance to the
// server registry, so the window of a server removed in the browser or config.yaml ends.
// S3's trust checks emit through the tap.
func attachNotify(ctx context.Context, cfg config.Config, c *core, creds secrets.Credentials, rt *serverRuntime,
	log *slog.Logger) (*notify.Service, *maint.Service, error) {
	out := &lateEmit{}
	ms, err := buildMaint(ctx, c, rt.fleet, out, log)
	if err != nil {
		return nil, nil, err
	}
	svc, err := buildNotify(ctx, cfg, c, creds, rt.fleet, ms, log)
	if err != nil {
		return nil, nil, err
	}
	out.p.Store(svc)
	return svc, ms, rt.setNotify(ctx, ms)
}

package fwcatalog

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/notify"
	"oob-manager/internal/store"
)

// Online check cadence (plan 08 §6.2).
const (
	CheckNowEvery   = 5 * time.Minute // one manual check per 5 minutes, whoever asks
	failuresToAlert = 3
	defaultTick     = 30 * time.Second
)

// Audit actions of the online check and the catalog in use (plan 08 §12).
const (
	ActionCheck   = "firmware.catalog.check"
	ActionConfirm = "firmware.catalog.confirm"
	ActionEnabled = "firmware.catalog.enabled_changed"
)

// Errors of the admin and operator actions.
var (
	ErrCheckOff    = errors.New("fwcatalog: the online check is off")
	ErrNoOnline    = errors.New("fwcatalog: no online source configured")
	ErrNothingHeld = errors.New("fwcatalog: no catalog is held")
)

// WaitError refuses a Check now within CheckNowEvery of the last one.
type WaitError struct{ Left time.Duration }

func (e *WaitError) Error() string { return "fwcatalog: checked moments ago" }

// Schedule is the runtime-managed part (Settings › General, read on every use).
type Schedule struct {
	Enabled bool
	Every   time.Duration
	Notify  string // urgent, all, off
}

// Pending is one newer, unskipped release the view shows now (for notifications).
type Pending struct {
	ServerID, ServerName, ComponentID, FQDD string
	Component, Running, Latest              string
	Urgent                                  bool
}

// FileSettings are the file-only keys, shown read-only in Settings.
type FileSettings struct {
	URL             string
	Fingerprints    []string
	AllowedNetworks []string
	AllowUnsigned   bool
	Systems         int
}

// Online wires the scheduled check; the zero value has none.
type Online struct {
	Fetcher  *Fetcher
	Schedule func() Schedule
	// Pending lists the view's newer releases (fwinventory) and InMaintenance tells a
	// server in a maintenance window (its updates wait); Emit sends (nil: none).
	Pending       func(ctx context.Context) []Pending
	InMaintenance func(serverID string) bool
	Emit          func(notify.Event)
	// Tick (0: 30 s) and FirstDelay (nil: 2–10 min with jitter) are test hooks.
	Tick       time.Duration
	FirstDelay func() time.Duration
}

// onlineState is the scheduler's state, guarded by Checker.mu.
type onlineState struct {
	failures   int // consecutive failed online checks
	alerted    bool
	byClass    map[string]int64
	lastManual time.Time
}

func (c *Checker) online() Online {
	if o := c.onl.Load(); o != nil {
		return *o
	}
	return c.cfg.Online
}

// SetOnline wires the scheduled check (serve builds the view its hooks read after the
// checker). Safe to call concurrently with readers.
func (c *Checker) SetOnline(o Online) { c.onl.Store(&o) }

func (c *Checker) schedule() Schedule {
	if o := c.online(); o.Schedule != nil {
		return o.Schedule()
	}
	return Schedule{}
}

// Run checks the catalog online on the schedule until ctx ends. It does nothing while
// the check is off; turning it on schedules a check within 2 minutes.
func (c *Checker) Run(ctx context.Context) {
	o := c.online()
	if o.Fetcher == nil {
		return
	}
	tick := o.Tick
	if tick <= 0 {
		tick = defaultTick
	}
	first := o.FirstDelay
	if first == nil {
		first = func() time.Duration { return 2*time.Minute + rand.N(8*time.Minute) } //nolint:gosec // G404: jitter
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	next := c.cfg.Now().Add(first())
	was := c.schedule().Enabled
	for {
		kicked := false
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-c.kick:
			kicked = true
		}
		s := c.schedule()
		now := c.cfg.Now()
		switch {
		case !s.Enabled:
			was = false
			continue
		case kicked:
			was, next = true, now
		case !was:
			was = true
			if soon := now.Add(min(first(), 2*time.Minute)); next.After(soon) {
				next = soon
			}
		}
		if now.Before(next) {
			continue
		}
		next = now.Add(c.checkOnline(ctx, s))
	}
}

// checkOnline runs one check and returns the wait until the next: the interval after a
// success, 1 h then 6 h after failures, then the interval again.
func (c *Checker) checkOnline(ctx context.Context, s Schedule) time.Duration {
	err := c.fetchAndImport(ctx)
	c.mu.Lock()
	if err == nil {
		c.st.failures, c.st.alerted = 0, false
		c.mu.Unlock()
		return s.Every
	}
	c.st.failures++
	c.st.byClass[catalog.Class(err)]++
	failures, alert := c.st.failures, c.st.failures >= failuresToAlert && !c.st.alerted
	if alert {
		c.st.alerted = true
	}
	c.mu.Unlock()
	if emit := c.online().Emit; alert && emit != nil {
		emit(notify.CatalogFailingEvent(catalog.Class(err), failures, c.cfg.Now()))
	}
	switch failures {
	case 1:
		return min(time.Hour, s.Every)
	case 2:
		return min(6*time.Hour, s.Every)
	default:
		return s.Every
	}
}

func (c *Checker) fetchAndImport(ctx context.Context) error {
	im := c.cfg.Importer
	etag, lm := c.lastOnlineValidators(ctx)
	got, err := c.online().Fetcher.Fetch(ctx, im.Dir, etag, lm)
	if err != nil {
		im.Record(ctx, catalog.Class(err), err)
		im.audit(ctx, Input{Origin: OriginOnline}, "firmware.catalog.failed",
			map[string]any{"origin": OriginOnline, "class": catalog.Class(err)}, audit.ResultError, catalog.Class(err))
		return err
	}
	if got.NotModified {
		im.Record(ctx, "not_modified", nil)
		c.notifyNew(ctx) // updates that waited (maintenance ended, a scan found an old version)
		return nil
	}
	if _, err := im.Import(ctx, Input{Origin: OriginOnline, File: got.File, Sig: got.Sig, ETag: got.ETag,
		LastModified: got.LastModified}); err != nil {
		return err
	}
	c.Invalidate()
	c.notifyNew(ctx)
	return nil
}

// lastOnlineValidators are the ETag and Last-Modified of the newest online import that
// is in use or held (a held catalog is not downloaded again every interval).
func (c *Checker) lastOnlineValidators(ctx context.Context) (string, string) {
	imps, err := c.cfg.Repo.Imports(ctx, c.source(), 5)
	if err != nil {
		return "", ""
	}
	for _, imp := range imps {
		if imp.State != store.CatalogReplaced && imp.Origin == OriginOnline {
			return imp.ETag, imp.LastModified
		}
	}
	return "", ""
}

// notifyNew sends one message for the updates not notified before (plan 08 §13). It runs
// after every online check (a 304 too), upload, confirmation and fleet change, so the
// updates of a server in maintenance go out with the first of those after the window.
// The notify level filters what is sent, but everything seen is marked so switching the
// level later never floods. Marking commits before sending: an update whose message is
// dropped (a full queue, a crash in between) is not sent again.
func (c *Checker) notifyNew(ctx context.Context) {
	o := c.online()
	if o.Pending == nil {
		return
	}
	var rows []store.FirmwareUpdateNotifiedRow
	byKey := map[string]Pending{}
	for _, p := range o.Pending(ctx) {
		if o.InMaintenance != nil && o.InMaintenance(p.ServerID) {
			continue
		}
		rows = append(rows, store.FirmwareUpdateNotifiedRow{ServerID: p.ServerID, ComponentID: p.ComponentID, FQDD: p.FQDD,
			Version: p.Latest, NotifiedAt: c.cfg.Now()})
		byKey[p.ServerID+"\x00"+p.ComponentID+"\x00"+p.FQDD+"\x00"+p.Latest] = p
	}
	fresh, err := c.cfg.Updates.MarkNotified(ctx, rows)
	if err != nil {
		c.cfg.Logger.Warn("fwcatalog: notified updates not recorded", "err", err)
		return
	}
	level := c.schedule().Notify
	var ups []notify.FirmwareUpdate
	for _, r := range fresh {
		p := byKey[r.ServerID+"\x00"+r.ComponentID+"\x00"+r.FQDD+"\x00"+r.Version]
		if level == "off" || (level != "all" && !p.Urgent) {
			continue
		}
		ups = append(ups, notify.FirmwareUpdate{ServerName: p.ServerName, Component: p.Component, Running: p.Running,
			Latest: p.Latest, Urgent: p.Urgent})
	}
	if len(ups) > 0 && o.Emit != nil {
		o.Emit(notify.FirmwareUpdatesEvent(ups, c.cfg.Now()))
	}
}

// CheckNow queues an immediate online check (operator). It is refused while the check
// is off, and within CheckNowEvery of the last manual check (*WaitError); both are
// audited by the caller's refusal path, the request itself here.
func (c *Checker) CheckNow(ctx context.Context, a admin.Actor) error {
	if c.online().Fetcher == nil {
		return ErrNoOnline
	}
	if !c.schedule().Enabled {
		return ErrCheckOff
	}
	c.mu.Lock()
	now := c.cfg.Now()
	if left := c.st.lastManual.Add(CheckNowEvery).Sub(now); !c.st.lastManual.IsZero() && left > 0 && !now.Before(c.st.lastManual) {
		c.mu.Unlock()
		return &WaitError{Left: left}
	}
	c.st.lastManual = now
	c.mu.Unlock()
	select {
	case c.kick <- struct{}{}:
	default: // a check is already queued
	}
	return c.audit(ctx, c.entry(a, "", ActionCheck, nil))
}

// audit writes an ok audit row for an event that changes nothing the view shows.
func (c *Checker) audit(ctx context.Context, e audit.Entry) error {
	e.Result = audit.ResultOK
	if _, err := c.cfg.Audit.Record(ctx, e); err != nil {
		c.cfg.Logger.Error("fwcatalog: audit failed", "action", e.Action, "err", err)
		return err
	}
	return nil
}

// Upload imports a catalog file an admin uploaded (signature required unless
// allow_unsigned): the same pipeline as the online check.
func (c *Checker) Upload(ctx context.Context, a admin.Actor, gz io.Reader, sig []byte) (Result, error) {
	im := c.cfg.Importer
	in := Input{Origin: OriginUpload, Sig: sig, By: a.Username, AuthMethod: a.Method, Role: string(a.Role), IP: a.IP}
	file, err := Stage(im.Dir, gz)
	if err != nil {
		im.Record(ctx, catalog.Class(err), err)
		im.audit(ctx, in, "firmware.catalog.failed", map[string]any{"origin": OriginUpload, "class": catalog.Class(err)},
			audit.ResultError, catalog.Class(err))
		return Result{}, err
	}
	in.File = file
	res, err := im.Import(ctx, in)
	if err != nil {
		return Result{}, err
	}
	c.Invalidate()
	c.notifyNew(ctx)
	return res, nil
}

// ConfirmHeld makes the held catalog the admin saw (by its import ID) active: a held
// catalog replaced since the page was shown is refused (ErrNothingHeld).
func (c *Checker) ConfirmHeld(ctx context.Context, a admin.Actor, importID int64) error {
	held, ok, err := c.cfg.Repo.Import(ctx, c.source(), store.CatalogHeld)
	if err != nil {
		return err
	}
	if !ok || held.ID != importID {
		return ErrNothingHeld
	}
	ok, err = c.cfg.Repo.ActivateHeld(ctx, c.source(), importID)
	if err == nil && !ok {
		return ErrNothingHeld
	}
	params := map[string]any{"version": held.Version, "sha256": held.SHA256, "signer": held.Signer, "kept": held.Kept}
	if err = c.finish(ctx, c.entry(a, "", ActionConfirm, params), err); err != nil {
		return err
	}
	c.notifyNew(ctx)
	return nil
}

// EnabledChanged audits a change of the online check switch (the settings service audits
// the save itself).
func (c *Checker) EnabledChanged(ctx context.Context, a admin.Actor, before, after bool) {
	_ = c.audit(ctx, c.entry(a, "", ActionEnabled, map[string]any{"before": before, "after": after}))
}

// File is the file-only configuration, for Settings.
func (c *Checker) File() FileSettings { return c.cfg.File }

// Metrics is the scheduler's state for /metrics.
func (c *Checker) Metrics(ctx context.Context) (published, lastCheck time.Time, lastResult string, failures map[string]int64) {
	st := c.Status(ctx)
	if st.Active != nil {
		published = st.Active.PublishedAt
	}
	if st.LastCheck != nil {
		lastCheck, lastResult = st.LastCheck.At, st.LastCheck.Result
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	failures = make(map[string]int64, len(c.st.byClass))
	for k, v := range c.st.byClass {
		failures[k] = v
	}
	return published, lastCheck, lastResult, failures
}

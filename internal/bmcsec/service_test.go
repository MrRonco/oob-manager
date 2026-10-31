package bmcsec

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
	"oob-manager/internal/notify"
	"oob-manager/internal/store"
)

var admin1 = admin.Actor{UserID: "u-root", Username: "root", Role: authz.RoleAdmin, IP: "192.0.2.7", Method: "local"}

// fakeFleet is a fleet.Reader over fixed states.
type fakeFleet struct {
	mu     sync.Mutex
	states map[string]fleet.ServerState
	order  []string
}

func (f *fakeFleet) Servers() []fleet.ServerState {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fleet.ServerState
	for _, id := range f.order {
		out = append(out, f.states[id])
	}
	return out
}

func (f *fakeFleet) Server(id string) (fleet.ServerState, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.states[id]
	return s, ok
}

func (f *fakeFleet) Polled() bool { return true }

func (f *fakeFleet) put(s fleet.ServerState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.states[s.ID]; !ok {
		f.order = append(f.order, s.ID)
	}
	f.states[s.ID] = s
}

func (f *fakeFleet) drop(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.states, id)
	f.order = slices.DeleteFunc(f.order, func(s string) bool { return s == id })
}

type svcEnv struct {
	t      *testing.T
	db     *store.DB
	fl     *fakeFleet
	svc    *Service
	mu     sync.Mutex
	now    time.Time
	sent   []notify.Event
	reruns []string
	rerun  error
	// addrs overrides a server's configured BMC address (default goodAddr); noInputs lists
	// servers the registry no longer knows (Inputs reports !ok).
	addrs    map[string]string
	noInputs map[string]bool
	audit    *flakyAudit
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func (e *svcEnv) clock() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.now }

func (e *svcEnv) advance(d time.Duration) { e.mu.Lock(); e.now = e.now.Add(d); e.mu.Unlock() }

func (e *svcEnv) events() []notify.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.sent)
}

func newSvcEnv(t *testing.T) *svcEnv {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e := &svcEnv{t: t, db: db, now: now, fl: &fakeFleet{states: map[string]fleet.ServerState{}}, addrs: map[string]string{},
		noInputs: map[string]bool{}}
	e.audit = &flakyAudit{Recorder: audit.NewLogger(db.Audit(), nil, e.clock, quietLog())}
	e.svc = e.open()
	return e
}

func (e *svcEnv) open() *Service {
	e.t.Helper()
	svc, err := New(context.Background(), Config{DB: e.db, Audit: e.audit,
		Fleet:  e.fl,
		Inputs: e.inputs,
		Rerun: func(id string) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.reruns = append(e.reruns, id)
			return e.rerun
		},
		Emit:       func(ev notify.Event) { e.mu.Lock(); e.sent = append(e.sent, ev); e.mu.Unlock() },
		ServerName: func(id string) string { return "Server " + id },
		Logger:     quietLog(), Now: e.clock})
	if err != nil {
		e.t.Fatal(err)
	}
	return svc
}

// serve puts a server with posture p into the fleet.
func (e *svcEnv) serve(id string, p bmc.Posture) {
	e.fl.put(fleet.ServerState{ID: id, Name: "Server " + id, Posture: p, HasPosture: true, PostureAsOf: e.clock(),
		PostureEnabled: true, PostureEvery: 6 * time.Hour})
}

func (e *svcEnv) auditActions() []string {
	e.t.Helper()
	rows, err := e.db.Audit().List(context.Background(), 0, store.MaxAuditPage)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.Action+":"+r.Result+":"+r.ErrorClass)
	}
	return out
}

func withIPMI(p bmc.Posture, v bool) bmc.Posture {
	p.Redfish.Protocols.IPMI = bmc.FactOf(v, "np")
	return p
}

func TestReportAppliesAcceptances(t *testing.T) {
	e := newSvcEnv(t)
	if _, ok := e.svc.Report("srv"); ok {
		t.Fatal("no posture yet")
	}
	e.serve("srv", withIPMI(good(), true))
	r, ok := e.svc.Report("srv")
	if !ok || r.Counts().Warn != 1 {
		t.Fatalf("report %+v", r.Counts())
	}
	if err := e.accept("srv", "svc.ipmi", " the UPS card needs it "); err != nil {
		t.Fatal(err)
	}
	r, _ = e.svc.Report("srv")
	f := find(t, r, "svc.ipmi")
	if f.Accepted == nil || f.Accepted.By != "root" || f.Accepted.Comment != "the UPS card needs it" || !f.Accepted.At.Equal(now) {
		t.Fatalf("accepted %+v", f.Accepted)
	}
	if c := r.Counts(); c.Warn != 0 || c.Accepted != 1 {
		t.Fatalf("an accepted finding stops counting: %+v", c)
	}
	if got := e.auditActions(); !slices.Contains(got, ActionAccept+":ok:") {
		t.Fatalf("audit %v", got)
	}
}

func TestAcceptRefusals(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	if err := e.accept("srv", "svc.ipmi", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no report: %v", err)
	}
	e.serve("srv", withIPMI(good(), true))
	if err := e.accept("srv", "svc.ipmi", strings.Repeat("a", MaxComment)); err != nil {
		t.Fatalf("a comment of exactly %d bytes: %v", MaxComment, err)
	}
	for _, bad := range []string{"", "  ", "two\nlines", strings.Repeat("a", MaxComment+1)} {
		if err := e.accept("srv", "svc.ipmi", bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("comment %q: %v", bad, err)
		}
	}
	if err := e.accept("srv", "svc.telnet", "fine"); !errors.Is(err, ErrNotProblem) {
		t.Fatalf("a passing check: %v", err)
	}
	if err := e.accept("srv", "no.such", "fine"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown check: %v", err)
	}
	none, err := New(ctx, Config{Fleet: e.fl, Inputs: func(string) (Inputs, bool) { return goodInputs(), true }})
	if err != nil {
		t.Fatal(err)
	}
	if err := none.Accept(ctx, admin1, "srv", "svc.ipmi", "x", ""); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no database: %v", err)
	}
}

func TestUnaccept(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	e.serve("srv", withIPMI(good(), true))
	if err := e.accept("srv", "svc.ipmi", "ok"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Unaccept(ctx, admin1, "srv", "svc.ipmi"); err != nil {
		t.Fatal(err)
	}
	if r, _ := e.svc.Report("srv"); find(t, r, "svc.ipmi").Accepted != nil {
		t.Fatal("still accepted")
	}
	if err := e.svc.Unaccept(ctx, admin1, "srv", "svc.ipmi"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second removal: %v", err)
	}
	if got := e.auditActions(); !slices.Contains(got, ActionUnaccept+":ok:") {
		t.Fatalf("audit %v", got)
	}
}

func TestAcceptanceEndsWhenTheFindingChanges(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	p := withIPMI(good(), true)
	p.Web.Cert.NotAfter = now.Add(10 * 24 * time.Hour)
	e.serve("srv", p)
	for _, id := range []string{"svc.ipmi", "tls.cert_expiry"} {
		if err := e.accept("srv", id, "accepted for now"); err != nil {
			t.Fatal(err)
		}
	}
	// IPMI is turned off (resolved); the certificate is replaced by another one that also
	// expires soon (changed: a new subject). Both acceptances end, each with its reason.
	p = withIPMI(good(), false)
	p.Web.Cert.NotAfter, p.Web.Cert.SHA256 = now.Add(10*24*time.Hour), "new"
	e.serve("srv", p)
	e.svc.Tick(ctx)
	r, _ := e.svc.Report("srv")
	if f := find(t, r, "tls.cert_expiry"); f.Accepted != nil || f.Result != Warn {
		t.Fatalf("a new certificate is a new finding: %+v", f)
	}
	rows, err := e.db.Security().Accepts(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("both acceptances end: %+v %v", rows, err)
	}
	var reasons []string
	recs, _ := e.db.Audit().List(ctx, 0, store.MaxAuditPage)
	for _, rec := range recs {
		if rec.Action == ActionUnaccept && rec.Principal == "system" {
			reasons = append(reasons, rec.ParamsJSON)
		}
	}
	if len(reasons) != 2 {
		t.Fatalf("system ends, audited with the reason: %v", reasons)
	}
}

func TestAcceptanceKeptWhileUnreadable(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	e.serve("srv", withIPMI(good(), true))
	if err := e.accept("srv", "svc.ipmi", "ok"); err != nil {
		t.Fatal(err)
	}
	p := good()
	p.Redfish.Protocols = bmc.ProtocolFacts{Read: bmc.Section{State: bmc.ReadForbidden}}
	e.serve("srv", p)
	e.svc.Tick(ctx)
	e.fl.drop("srv")
	e.svc.Tick(ctx)
	if rows, _ := e.db.Security().Accepts(ctx); len(rows) != 1 {
		t.Fatalf("an unreadable or absent server keeps its acceptance: %+v", rows)
	}
}

func TestRerunCooldown(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	e.serve("srv", good())
	if err := e.svc.Rerun(ctx, admin1, "srv"); err != nil {
		t.Fatal(err)
	}
	var cd *CooldownError
	if err := e.svc.Rerun(ctx, admin1, "srv"); !errors.As(err, &cd) || cd.Left != DefaultRerunCooldown {
		t.Fatalf("cooldown: %v", err)
	}
	if st := e.svc.Status("srv"); st.CooldownLeft != DefaultRerunCooldown {
		t.Fatalf("status cooldown %v", st.CooldownLeft)
	}
	e.advance(DefaultRerunCooldown)
	if err := e.svc.Rerun(ctx, admin1, "srv"); err != nil {
		t.Fatalf("after the cooldown: %v", err)
	}
	e.mu.Lock()
	e.rerun = fleet.ErrPaused
	e.mu.Unlock()
	e.advance(DefaultRerunCooldown)
	if err := e.svc.Rerun(ctx, admin1, "srv"); !errors.Is(err, fleet.ErrPaused) {
		t.Fatalf("fleet refusal: %v", err)
	}
	if st := e.svc.Status("srv"); st.CooldownLeft != 0 {
		t.Fatalf("a refused re-run gives the cooldown back: %v", st.CooldownLeft)
	}
	got := e.auditActions()
	if !slices.Contains(got, ActionRerun+":ok:") || !slices.Contains(got, ActionRerun+":denied:cooldown") ||
		!slices.Contains(got, ActionRerun+":error:paused") {
		t.Fatalf("audit %v", got)
	}
	if len(e.reruns) != 3 {
		t.Fatalf("fleet asked %d times", len(e.reruns))
	}
	if err := e.svc.Rerun(ctx, admin1, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown server: %v", err)
	}
}

func TestStatusFollowsTheFleet(t *testing.T) {
	e := newSvcEnv(t)
	e.fl.put(fleet.ServerState{ID: "srv", PostureEnabled: true, PostureRunning: true, PostureRequested: true,
		PostureError: bmc.ClassTimeout, PostureEvery: 6 * time.Hour})
	st := e.svc.Status("srv")
	if !st.Enabled || st.HasReport || !st.Running || !st.Requested || st.Error != bmc.ClassTimeout || !st.NextAround.IsZero() {
		t.Fatalf("status %+v", st)
	}
	e.serve("srv", good())
	if st := e.svc.Status("srv"); !st.HasReport || !st.AsOf.Equal(now) || !st.NextAround.Equal(now.Add(6*time.Hour)) {
		t.Fatalf("status %+v", st)
	}
	if st := e.svc.Status("none"); st.Enabled {
		t.Fatalf("unknown server %+v", st)
	}
}

// inputs is the registry's view: goodInputs at the configured address, unless the test
// moved the server (addrs) or removed it (noInputs).
func (e *svcEnv) inputs(id string) (Inputs, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if id == "" || e.noInputs[id] {
		return Inputs{}, false
	}
	in := goodInputs()
	if a, ok := e.addrs[id]; ok {
		in.Address = a
	}
	return in, true
}

func (e *svcEnv) setAddr(id, addr string) { e.mu.Lock(); e.addrs[id] = addr; e.mu.Unlock() }

func (e *svcEnv) forget(id string) { e.mu.Lock(); e.noInputs[id] = true; e.mu.Unlock() }

// unacceptReasons are the reasons of the system's acceptance endings, in audit order.
func (e *svcEnv) unacceptReasons() []string {
	e.t.Helper()
	recs, err := e.db.Audit().List(context.Background(), 0, store.MaxAuditPage)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, rec := range recs {
		if rec.Action == ActionUnaccept && rec.Principal == "system" {
			out = append(out, rec.ParamsJSON)
		}
	}
	return out
}

// withExpiredLicense adds an expired production licence whose description is longer than
// the stored subject: the finding's subject is clipped, its hash is of the whole text.
func withExpiredLicense(p bmc.Posture, description string) bmc.Posture {
	p.Redfish.Licenses = p.Redfish.Licenses.WithLicenses([]bmc.LicenseEntry{
		{Description: description, Type: "Production", Expires: now.Add(-48 * time.Hour)}})
	return p
}

func TestAcceptanceBindsToTheWholeSubject(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	long := strings.Repeat("L", 300)
	e.serve("srv", withExpiredLicense(good(), long))
	r, _ := e.svc.Report("srv")
	f := find(t, r, "fw.license")
	if f.Result != Warn || len(f.Subject) != maxSubject || len(f.SubjectHash) != 64 {
		t.Fatalf("finding %s subject %d bytes hash %q", f.Result, len(f.Subject), f.SubjectHash)
	}
	if err := e.accept("srv", "fw.license", "renewal ordered"); err != nil {
		t.Fatal(err)
	}
	rows, _ := e.db.Security().Accepts(ctx)
	if len(rows) != 1 || rows[0].SubjectHash != f.SubjectHash || rows[0].Subject != f.Subject || rows[0].ServerAddr != goodAddr {
		t.Fatalf("stored %+v", rows)
	}
	// Another licence whose description differs only beyond the clipped subject.
	e.serve("srv", withExpiredLicense(good(), long[:299]+"X"))
	r, _ = e.svc.Report("srv")
	if g := find(t, r, "fw.license"); g.Subject != f.Subject || g.SubjectHash == f.SubjectHash || g.Accepted != nil {
		t.Fatalf("the clipped subject is the same, the hash and the acceptance must not be: %+v", g)
	}
	e.svc.Tick(ctx)
	if rows, _ = e.db.Security().Accepts(ctx); len(rows) != 0 {
		t.Fatalf("an acceptance must not cover a finding that changed beyond the clipped subject: %+v", rows)
	}
	if reasons := e.unacceptReasons(); len(reasons) != 1 || !strings.Contains(reasons[0], `"changed"`) {
		t.Fatalf("reasons %v", reasons)
	}
}

func TestAcceptanceEndsWhenTheServerMoves(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	e.serve("srv", withIPMI(good(), true))
	if err := e.accept("srv", "svc.ipmi", "known"); err != nil {
		t.Fatal(err)
	}
	e.svc.Tick(ctx)
	if rows, _ := e.db.Security().Accepts(ctx); len(rows) != 1 || rows[0].ServerAddr != goodAddr {
		t.Fatalf("kept at the same address: %+v", rows)
	}
	// The admin points the server ID at another BMC: the acceptance was not made for it,
	// whatever that BMC reports, and it stops applying at once, before any sweep.
	e.setAddr("srv", "192.0.2.99:443")
	if r, _ := e.svc.Report("srv"); r.Counts().Accepted != 0 || r.Counts().Warn != 1 {
		t.Fatalf("applied after the move: %+v", r.Counts())
	}
	e.svc.Tick(ctx)
	if rows, _ := e.db.Security().Accepts(ctx); len(rows) != 0 {
		t.Fatalf("an acceptance must not follow the server ID to another BMC: %+v", rows)
	}
	if reasons := e.unacceptReasons(); len(reasons) != 1 || !strings.Contains(reasons[0], `"server changed"`) {
		t.Fatalf("reasons %v", reasons)
	}
	// Accepting needs a configured address to bind to.
	e.forget("srv")
	if err := e.accept("srv", "svc.ipmi", "known"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("accept without inputs: %v", err)
	}
}

// TestAcceptanceKeptWhileTheRegistryForgetsTheServer: while the registry has no inputs
// for a server (the window of a removal, or a server that left config.yaml), nothing is
// evaluated and its acceptance is neither ended as "resolved" nor reported.
func TestAcceptanceKeptWhileTheRegistryForgetsTheServer(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	e.serve("srv", withIPMI(good(), true))
	if err := e.accept("srv", "svc.ipmi", "known"); err != nil {
		t.Fatal(err)
	}
	e.forget("srv")
	if _, ok := e.svc.Report("srv"); ok {
		t.Fatal("a server without inputs has no report")
	}
	e.svc.Tick(ctx)
	if rows, _ := e.db.Security().Accepts(ctx); len(rows) != 1 {
		t.Fatalf("acceptance ended while the server had no inputs: %+v", rows)
	}
	if f, _ := securityEvents(e.events()); len(f) != 0 {
		t.Fatalf("notified without inputs: %+v", f)
	}
}

// accept accepts check on id as the admin, for the finding the page shows right now.
func (e *svcEnv) accept(id, check, comment string) error {
	seen := ""
	if r, ok := e.svc.Report(id); ok {
		if f, found := r.Finding(check); found {
			seen = f.Seen()
		}
	}
	return e.svc.Accept(context.Background(), admin1, id, check, comment, seen)
}

// TestAcceptRefusesAFindingThatChanged: the form carries the result and subject hash the
// admin looked at; a finding that differs now is not accepted, and nothing is written.
func TestAcceptRefusesAFindingThatChanged(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	e.serve("srv", withIPMI(good(), true))
	r, _ := e.svc.Report("srv")
	f := find(t, r, "svc.ipmi")
	stale := []string{"", "fail|" + f.SubjectHash, "warn|" + strings.Repeat("0", 64), string(f.Result) + "|"}
	for _, seen := range stale {
		if err := e.svc.Accept(ctx, admin1, "srv", "svc.ipmi", "known", seen); !errors.Is(err, ErrChanged) {
			t.Errorf("seen %q: %v, want ErrChanged", seen, err)
		}
	}
	if rows, _ := e.db.Security().Accepts(ctx); len(rows) != 0 {
		t.Fatalf("a refused acceptance was stored: %+v", rows)
	}
	if got := e.auditActions(); slices.Contains(got, ActionAccept+":ok:") {
		t.Fatalf("a refused acceptance was audited as ok: %v", got)
	}
	if err := e.svc.Accept(ctx, admin1, "srv", "svc.ipmi", "known", f.Seen()); err != nil {
		t.Fatalf("the finding as shown: %v", err)
	}
}

// flakyAudit is the audit logger with a switch that makes Record fail (the database is
// gone, the disk is full): the service must then refuse the action.
type flakyAudit struct {
	Recorder
	fail atomic.Bool
}

var errAuditDown = errors.New("audit: no space left on device")

func (f *flakyAudit) Record(ctx context.Context, e audit.Entry) (store.AuditRecord, error) {
	if f.fail.Load() {
		return store.AuditRecord{}, errAuditDown
	}
	return f.Recorder.Record(ctx, e)
}

// TestRerunIsAuditedFailClosed: like a power action, a re-run that cannot be audited is
// not requested; the cooldown reservation is given back, and the next request works.
func TestRerunIsAuditedFailClosed(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	e.serve("srv", good())
	e.audit.fail.Store(true)
	if err := e.svc.Rerun(ctx, admin1, "srv"); !errors.Is(err, errAuditDown) {
		t.Fatalf("re-run without an audit row: %v", err)
	}
	if len(e.reruns) != 0 {
		t.Fatal("the fleet was asked although the request could not be audited")
	}
	if st := e.svc.Status("srv"); st.CooldownLeft != 0 {
		t.Fatalf("a refused request keeps the cooldown: %v", st.CooldownLeft)
	}
	e.audit.fail.Store(false)
	if err := e.svc.Rerun(ctx, admin1, "srv"); err != nil {
		t.Fatalf("after the audit log is back: %v", err)
	}
	got := e.auditActions()
	if len(e.reruns) != 1 || !slices.Contains(got, ActionRerun+":started:") || !slices.Contains(got, ActionRerun+":ok:") {
		t.Fatalf("reruns %v audit %v", e.reruns, got)
	}
	// The started row comes before the fleet is asked, the ok row after.
	if si, oi := slices.Index(got, ActionRerun+":started:"), slices.Index(got, ActionRerun+":ok:"); si > oi {
		t.Fatalf("row order %v", got)
	}
}

// TestInfoResolvesAnAcceptance: a finding that drops to Info (IPMI accounts while IPMI
// over LAN is off) is resolved for the acceptance's purpose, like a pass.
func TestInfoResolvesAnAcceptance(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	p := withAccounts(withIPMI(good(), true), bmc.Account{UserName: "root", Enabled: on(true, "e"), IPMI: on(true, "a")})
	e.serve("srv", p)
	if err := e.accept("srv", "acct.ipmi_sol", "the UPS card"); err != nil {
		t.Fatal(err)
	}
	e.serve("srv", withIPMI(p, false)) // IPMI over LAN off: the check is informational now
	e.svc.Tick(ctx)
	if rows, _ := e.db.Security().Accepts(ctx); len(rows) != 0 {
		t.Fatalf("an acceptance of an informational finding: %+v", rows)
	}
	if reasons := e.unacceptReasons(); len(reasons) != 1 || !strings.Contains(reasons[0], `"resolved"`) {
		t.Fatalf("reasons %v", reasons)
	}
}

func (f *flakyAudit) RecordTx(ctx context.Context, tx *store.Tx, e audit.Entry) (store.AuditRecord, error) {
	if f.fail.Load() {
		return store.AuditRecord{}, errAuditDown
	}
	return f.Recorder.RecordTx(ctx, tx, e)
}

// TestAcceptanceDoesNotFollowARecreatedServer: the registry removes a server (its rows go
// with it) and one with the same ID is created at another address before any sweep ran.
// The stale in-memory acceptance must not apply to the new server, the finding is
// notified, and the next sweep brings memory back in line with the database.
func TestAcceptanceDoesNotFollowARecreatedServer(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	e.serve("srv", withIPMI(good(), true))
	if err := e.accept("srv", "svc.ipmi", "known"); err != nil {
		t.Fatal(err)
	}
	if err := e.db.Security().DeleteServer(ctx, "srv"); err != nil {
		t.Fatal(err)
	}
	e.setAddr("srv", "192.0.2.99:443")
	e.serve("srv", withIPMI(good(), true))
	r, _ := e.svc.Report("srv")
	if c := r.Counts(); c.Accepted != 0 || c.Warn != 1 {
		t.Fatalf("a stale acceptance applied to the new server: %+v", c)
	}
	e.svc.Tick(ctx)
	if f, _ := securityEvents(e.events()); len(f) != 1 {
		t.Fatalf("the new server's finding is notified: %+v", f)
	}
	if n := len(*e.svc.accepts.Load()); n != 0 {
		t.Fatalf("the in-memory copy kept %d acceptance(s) the database no longer has", n)
	}
	if err := e.svc.Unaccept(ctx, admin1, "srv", "svc.ipmi"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unaccept: %v", err)
	}
}

// TestAcceptanceNotAppliedWhileTheSweepCannotEndIt: with the audit log down the sweep
// cannot delete a stale acceptance (fail closed), but it is not applied either: the
// binding holds where acceptances are applied, not only where rows are deleted.
func TestAcceptanceNotAppliedWhileTheSweepCannotEndIt(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	e.serve("srv", withIPMI(good(), true))
	if err := e.accept("srv", "svc.ipmi", "known"); err != nil {
		t.Fatal(err)
	}
	e.setAddr("srv", "192.0.2.99:443")
	e.audit.fail.Store(true)
	e.svc.Tick(ctx)
	if rows, _ := e.db.Security().Accepts(ctx); len(rows) != 1 {
		t.Fatalf("without an audit row the acceptance must stay in the database: %+v", rows)
	}
	r, _ := e.svc.Report("srv")
	if c := r.Counts(); c.Accepted != 0 || c.Warn != 1 {
		t.Fatalf("an acceptance for another address applied: %+v", c)
	}
	if f, _ := securityEvents(e.events()); len(f) != 1 {
		t.Fatalf("the finding is notified while the stale acceptance lingers: %+v", f)
	}
	e.audit.fail.Store(false)
	e.svc.Tick(ctx)
	if rows, _ := e.db.Security().Accepts(ctx); len(rows) != 0 {
		t.Fatalf("the sweep ends it once it can be audited: %+v", rows)
	}
	if reasons := e.unacceptReasons(); len(reasons) != 1 || !strings.Contains(reasons[0], `"server changed"`) {
		t.Fatalf("reasons %v", reasons)
	}
}

// TestCleanComment: one line of text, 1 to 500 bytes; format characters (zero-width
// spaces, bidirectional overrides, the byte order mark) are removed rather than shown.
func TestCleanComment(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{" the UPS card ", "the UPS card", true},
		{"ok\u200b\u202e", "ok", true},
		{"\ufeff needed ", "needed", true},
		{strings.Repeat("a", MaxComment), strings.Repeat("a", MaxComment), true},
		{strings.Repeat("a", MaxComment+1), "", false},
		{"two\nlines", "", false},
		{"tab\there", "", false},
		{"", "", false},
		{"\u200b", "", false},
		{"bad\xffutf8", "", false},
	}
	for _, c := range cases {
		got, err := CleanComment(c.in)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("CleanComment(%q) = %q, %v; want %q, ok=%v", c.in, got, err, c.want, c.ok)
		}
	}
}

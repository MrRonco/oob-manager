package integrations

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/config"
	"oob-manager/internal/settings"
	"oob-manager/internal/tofu"
)

// TestTimeout bounds one Send test attempt (dial, handshake and write).
const TestTimeout = 5 * time.Second

// Update saves form values (see settings.UpdateIntegrations) after the full destination
// policy accepted the resulting address, then applies the new target. Order: the
// admin.integrations.update row is committed and queued on the CURRENT shipper, then
// the shipper is swapped, then admin.integrations.applied goes to the new one: the
// previous log server records who redirected the audit stream, and where to.
func (s *Service) Update(ctx context.Context, a admin.Actor, rev int64, form map[string]string,
	pin settings.PinOrigin) ([]settings.Change, error) {
	if err := s.checkDestination(ctx, form); err != nil {
		e := entry(a, settings.ActionIntegrationsUpdate, map[string]any{"rev": rev})
		e.Result, e.ErrorClass = audit.ResultDenied, ClassPolicy
		s.record(ctx, e)
		return nil, err
	}
	changes, err := s.cfg.Settings.UpdateIntegrations(ctx, a, rev, form, pin)
	if err != nil || len(changes) == 0 {
		return changes, err
	}
	s.Apply(ctx)
	return changes, nil
}

// Reset deletes one saved GELF value (settings.ResetIntegrations) and applies the result.
func (s *Service) Reset(ctx context.Context, a admin.Actor, rev int64, key string) ([]settings.Change, error) {
	changes, err := s.cfg.Settings.ResetIntegrations(ctx, a, rev, key)
	if err != nil || len(changes) == 0 {
		return changes, err
	}
	s.Apply(ctx)
	return changes, nil
}

// checkDestination applies the policy (allowed networks, own endpoints, every DNS
// answer) to the address the form would put in force when it would be enabled.
func (s *Service) checkDestination(ctx context.Context, form map[string]string) error {
	cur := s.cfg.Settings.Current().Integrations
	addr, enabled := cur.Address, cur.Enabled
	if v, ok := form[config.KeyGELFAddress]; ok {
		addr = strings.TrimSpace(v)
	}
	if v, ok := form[config.KeyGELFEnabled]; ok {
		enabled = strings.TrimSpace(v) == "on"
	}
	if !enabled || addr == "" || len(config.ValidateGELF(config.GELF{Address: addr})) > 0 {
		return nil // the settings validator reports shape errors with the field
	}
	if _, err := s.cfg.Policy.Resolve(ctx, addr); err != nil {
		return fmt.Errorf("%w: audit.gelf.address: %s", settings.ErrInvalid, reasonOf(err))
	}
	return nil
}

// Fingerprint fetches the certificate of the GELF server at hostport (handshake only:
// no GELF frame or other byte is sent) after the destination policy accepted it, and
// audits it: a started row before anything is dialled (no row, no dial), then the
// result (address, port, class). serverName, checked like the saved one, is sent as SNI.
func (s *Service) Fingerprint(ctx context.Context, a admin.Actor, hostport, serverName string) (tofu.CertInfo, error) {
	params := func() map[string]any { return map[string]any{"address": hostOf(hostport), "port": portOf(hostport)} }
	start := entry(a, ActionFingerprint, params())
	start.Result = audit.ResultStarted
	rec, rerr := s.cfg.Audit.Record(ctx, start)
	if rerr != nil {
		return tofu.CertInfo{}, rerr
	}
	all, err := s.cfg.Policy.ResolveAll(ctx, hostport)
	if err == nil && serverName != "" && len(config.ValidateGELF(config.GELF{Address: hostport, ServerName: serverName})) > 0 {
		err = &PolicyError{Class: ClassPolicy, Reason: "the server name must be a DNS name"}
	}
	info := tofu.CertInfo{}
	if err == nil {
		sni := serverName
		if sni == "" {
			sni = serverNameOf(hostport)
		}
		info, err = s.fetchEvery(ctx, all, tofu.Options{Dial: tofu.Dialer(s.cfg.Dial), ServerName: sni})
	}
	e := entry(a, ActionFingerprint, params())
	e.CorrelationID = rec.CorrelationID
	if class := fetchClass(err); class != "" {
		e.Result, e.ErrorClass = audit.ResultError, class
	}
	s.record(ctx, e)
	return info, err
}

// MaxFetchAnswers bounds how many DNS answers a fingerprint fetch visits (all at once).
const MaxFetchAnswers = 4

// FetchTimeout is the budget of one fingerprint request: resolving the name, then one
// round of dial and handshake. The answers are fetched in parallel, each within the
// tofu dial and handshake bounds, so the budget does not grow with their number.
const FetchTimeout = 2*tofu.DefaultDialTimeout + tofu.DefaultHandshakeTimeout

// ClassMultiCert is the class of a name whose answers present different certificates.
const ClassMultiCert = "multi_cert"

// fetchEvery fetches the certificate from every answer of the name (the shipper may
// connect to any of them) and requires them all to present the same leaf key, so the pin
// an admin confirms holds whichever answer is used. An IP literal is one answer. The
// answers (at most MaxFetchAnswers) are fetched concurrently; the first failure in
// answer order is reported. all is non-empty (ResolveAll).
func (s *Service) fetchEvery(ctx context.Context, all []netip.AddrPort, o tofu.Options) (tofu.CertInfo, error) {
	if len(all) > MaxFetchAnswers {
		return tofu.CertInfo{}, &PolicyError{Class: ClassMultiCert,
			Reason: "the name has more than 4 addresses; use the IP address of the log server"}
	}
	infos, errs := make([]tofu.CertInfo, len(all)), make([]error, len(all))
	var wg sync.WaitGroup
	for i, ap := range all {
		wg.Go(func() { infos[i], errs[i] = tofu.FetchTLS(ctx, ap, o) })
	}
	wg.Wait()
	for i, info := range infos {
		if errs[i] != nil {
			return tofu.CertInfo{}, errs[i]
		}
		if info.SPKI != infos[0].SPKI || info.Recommended() != infos[0].Recommended() {
			return tofu.CertInfo{}, &PolicyError{Class: ClassMultiCert,
				Reason: "the name's addresses present different certificates; use the IP address of one log server"}
		}
	}
	return infos[0], nil
}

func serverNameOf(hostport string) string { return serverName(config.GELF{Address: hostport}) }

// maxAuditHost bounds the typed host recorded in the audit row.
const maxAuditHost = 253

// hostOf and portOf split an address for the audit row ("" / 0 when it does not split;
// the host is truncated: it is what the admin typed, possibly refused).
func hostOf(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return ""
	}
	if len(h) > maxAuditHost {
		h = h[:maxAuditHost]
	}
	return h
}

func portOf(hostport string) int {
	_, p, err := net.SplitHostPort(hostport)
	n, perr := strconv.Atoi(p)
	if err != nil || perr != nil {
		return 0
	}
	return n
}

func fetchClass(err error) string {
	switch e := err.(type) {
	case nil:
		return ""
	case *PolicyError:
		return e.Class
	case *tofu.Error:
		return string(e.Class)
	default:
		return "error"
	}
}

// TestResult is the outcome of Send test.
type TestResult struct {
	OK              bool
	Class           string // failure class, "" when OK
	ConnectedBefore bool
	ConnectedAfter  bool
}

// SendTest writes one test frame synchronously through the running shipper (bounded
// to TestTimeout) and audits admin.integrations.gelf.test: a started row first (no row,
// no send), then the outcome with the shipper's connected flag before and after. A
// written frame is the only signal GELF gives: the server accepted the bytes.
func (s *Service) SendTest(ctx context.Context, a admin.Actor) TestResult {
	start := entry(a, ActionTest, map[string]any{})
	start.Result = audit.ResultStarted
	rec, rerr := s.cfg.Audit.Record(ctx, start)
	if rerr != nil {
		return TestResult{Class: ClassAudit}
	}
	sh := s.current()
	var r TestResult
	if sh == nil {
		r.Class = audit.ClassOff
	} else {
		r.ConnectedBefore = sh.Stats().Connected
		tctx, cancel := context.WithTimeout(ctx, TestTimeout)
		err := sh.Probe(tctx, testMessage(a.Username, s.cfg.Now()))
		cancel()
		r.OK, r.Class, r.ConnectedAfter = err == nil, audit.ErrorClassOf(err), sh.Stats().Connected
	}
	e := entry(a, ActionTest, map[string]any{"connected_before": r.ConnectedBefore, "connected_after": r.ConnectedAfter,
		"class": r.Class})
	e.CorrelationID = rec.CorrelationID
	if !r.OK {
		e.Result, e.ErrorClass = audit.ResultError, r.Class
	}
	s.record(ctx, e)
	return r
}

func testMessage(user string, now time.Time) audit.Message {
	return audit.Message{Host: audit.DefaultHost, Short: "oob-manager GELF test by " + user, Timestamp: now,
		Level: audit.LevelNotice, Fields: map[string]any{"log_type": "test", "principal": user}}
}

func entry(a admin.Actor, action string, params map[string]any) audit.Entry {
	params["target"] = "gelf"
	return audit.Entry{Principal: a.Username, AuthMethod: a.Method, Role: string(a.Role), SrcIP: a.IP,
		Action: action, Params: params, Result: audit.ResultOK}
}

func (s *Service) record(ctx context.Context, e audit.Entry) {
	if _, err := s.cfg.Audit.Record(ctx, e); err != nil {
		s.cfg.Logger.Error("integrations: audit record failed", "action", e.Action, "err", err)
	}
}

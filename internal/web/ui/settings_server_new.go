package ui

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/config"
	"oob-manager/internal/netpolicy"
	"oob-manager/internal/registry"
	"oob-manager/internal/tofu"
)

// ActionServerFingerprint is the audit action of a fingerprint fetch (it dials a BMC).
const ActionServerFingerprint = "admin.server.fingerprint"

var (
	pinFormPattern  = regexp.MustCompile(`^[0-9a-fA-F:\s]{64,95}$`)
	digitsPattern   = regexp.MustCompile(`^[0-9]{1,6}$`)
	tagSplitPattern = regexp.MustCompile(`[\s,]+`)
)

// newServerForm is step 1 of Add server: identity and connection.
type newServerForm struct {
	ID, Name, Tags, Kind, Address, Port, Pin string
}

type newServerView struct {
	StepUp    stepUpNote
	CSRF      string
	Form      newServerForm
	Kinds     []kindOption
	FormError string
	Invalid   string // the field the error is about
	Networks  string
	Locked    bool
}

type kindOption struct {
	Value, Label string
	Selected     bool
}

func kindOptions(selected string) []kindOption {
	all := []kindOption{{Value: "idrac9", Label: "Dell iDRAC9 (14G and later)"}, {Value: "idrac8", Label: "Dell iDRAC8 (13G)"},
		{Value: "redfish", Label: "Other Redfish BMC"}}
	for i := range all {
		all[i].Selected = all[i].Value == selected
	}
	return all
}

func (s *server) newServerPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderNewServer(w, r, sess, http.StatusOK, newServerForm{Kind: "idrac9", Port: "443"}, "", "")
}

func (s *server) renderNewServer(w http.ResponseWriter, r *http.Request, sess session, status int, f newServerForm,
	msg, field string) {
	v := newServerView{StepUp: s.stepUpNoteFor(r, sess), CSRF: s.csrf.issue(formSettings, sessionBinding(sess.token)),
		Form: f, Kinds: kindOptions(f.Kind), FormError: msg, Invalid: field, Locked: s.d.Servers.Current().Locked}
	v.StepUp.Next = "/settings/servers/new"
	var nets []string
	for _, p := range s.d.Servers.Policy().Networks {
		nets = append(nets, p.String())
	}
	v.Networks = strings.Join(nets, ", ")
	d := s.settingsLayout(r, sess, "Add server", v)
	d.Crumbs = []crumb{{"Settings", "/settings"}, {"Servers", "/settings/servers"}, {Label: "Add server"}}
	s.render(w, r, status, pageSettingsServerNew, d)
}

func newServerFormOf(form url.Values) newServerForm {
	g := func(k string) string { return strings.TrimSpace(form.Get(k)) }
	return newServerForm{ID: g("id"), Name: g("name"), Tags: g("tags"), Kind: g("kind"), Address: g("address"),
		Port: g("port"), Pin: g("pin")}
}

// target validates kind, address and port before anything is dialled: closed kinds,
// a port the config validator accepts, and the BMC address policy.
func (s *server) target(kind, address, port string) (netip.AddrPort, string, string) {
	switch config.BMCKind(kind) {
	case config.KindIDRAC8, config.KindIDRAC9, config.KindRedfish:
	default:
		return netip.AddrPort{}, "Choose a BMC kind from the list.", "kind"
	}
	n, err := strconv.Atoi(port)
	if !digitsPattern.MatchString(port) || err != nil || (n != config.DefaultBMCPort && (n < config.MinCustomPort || n > 65535)) {
		return netip.AddrPort{}, "The port must be 443 or 1024 to 65535.", "port"
	}
	addr, err := netpolicy.CheckBMCAddr(address, s.d.Servers.Policy())
	if err != nil {
		var pe *netpolicy.Error
		if errors.As(err, &pe) {
			return netip.AddrPort{}, "Address: " + pe.Reason() + ".", "address"
		}
		return netip.AddrPort{}, "Address: not allowed.", "address"
	}
	return netip.AddrPortFrom(addr, uint16(n)), "", "" //nolint:gosec // n is checked to be ≤ 65535
}

// newServerFingerprint fetches the HTTPS fingerprint of the typed address (step 2), or
// creates the server directly with a pasted pin.
func (s *server) newServerFingerprint(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	f := newServerFormOf(form)
	ap, msg, field := s.target(f.Kind, f.Address, f.Port)
	if msg != "" {
		s.renderNewServer(w, r, sess, http.StatusUnprocessableEntity, f, msg, field)
		return
	}
	if f.Pin != "" {
		if !s.allowChange(w, r, sess, authz.AdminServersManage) {
			return
		}
		pin, ok := normalisePin(f.Pin)
		if !ok {
			s.renderNewServer(w, r, sess, http.StatusUnprocessableEntity, f, "The fingerprint must be 64 hexadecimal digits.", "pin")
			return
		}
		s.create(w, r, sess, f, pin, "manual")
		return
	}
	info, err := s.fetchTLS(w, r, sess, ap, false, "")
	if err != nil {
		if err != errRateLimited {
			s.renderNewServer(w, r, sess, http.StatusUnprocessableEntity, f, fetchMessage(err), "address")
		}
		return
	}
	hidden := []kv{{"id", f.ID}, {"name", f.Name}, {"tags", f.Tags}, {"kind", f.Kind}, {"address", f.Address}, {"port", f.Port}}
	s.renderTOFU(w, r, sess, tofuView{Purpose: "Add server " + f.Name, Action: "/settings/servers", Cancel: "/settings/servers/new",
		Hidden: hidden, Button: "Confirm fingerprint and add the server"}, tofu.KindTLS, ap, info.SPKI, certFacts(sess, info))
}

func (s *server) createServer(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	f := newServerFormOf(form)
	ap, msg, field := s.target(f.Kind, f.Address, f.Port)
	if msg != "" {
		s.renderNewServer(w, r, sess, http.StatusUnprocessableEntity, f, msg, field)
		return
	}
	value := form.Get("value")
	if err := s.d.Proofs.Verify(s.claim(sess, r.URL.Path, tofu.KindTLS, ap, value), form.Get("proof")); err != nil {
		s.renderNewServer(w, r, sess, http.StatusUnprocessableEntity, f, proofMessage(err), "")
		return
	}
	s.create(w, r, sess, f, value, "tofu")
}

func (s *server) create(w http.ResponseWriter, r *http.Request, sess session, f newServerForm, pin, via string) {
	port, _ := strconv.Atoi(f.Port)
	d := registry.Draft{ID: f.ID, Name: f.Name, Tags: splitTags(f.Tags), Kind: config.BMCKind(f.Kind), Address: f.Address,
		Port: port, TLSPin: pin, PinVia: via}
	if _, err := s.d.Servers.Create(r.Context(), actor(r, sess), d); err != nil {
		status, msg := s.serverError(err)
		if status == http.StatusInternalServerError || status == http.StatusForbidden {
			s.errorPage(w, r, status, msg)
			return
		}
		s.renderNewServer(w, r, sess, status, f, msg, invalidServerField(msg))
		return
	}
	redirectLocal(w, r, "/settings/servers/"+f.ID+"?done=server-created")
}

// errRateLimited means the response (429) is already written.
var errRateLimited = errors.New("rate limited")

// fetchTLS fetches the certificate at ap (handshake only), audited, rate limited.
func (s *server) fetchTLS(w http.ResponseWriter, r *http.Request, sess session, ap netip.AddrPort, rsaKex bool,
	serverID string) (tofu.CertInfo, error) {
	if !s.allowFingerprint(w, r, sess) {
		return tofu.CertInfo{}, errRateLimited
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*tofu.DefaultDialTimeout+tofu.DefaultHandshakeTimeout)
	defer cancel()
	info, err := s.d.Prober.FetchTLS(ctx, ap, rsaKex)
	s.auditFetch(r, sess, serverID, ap, "tls", err)
	return info, err
}

func (s *server) allowFingerprint(w http.ResponseWriter, r *http.Request, sess session) bool {
	if ok, wait := s.fpLimit.allow("user:" + sess.id.User.ID); !ok {
		_ = s.record(r, audit.Entry{Principal: sess.id.User.Username, Role: string(sess.id.User.Role),
			Action: ActionServerFingerprint, Result: audit.ResultDenied, ErrorClass: "rate_limited"})
		setRetryAfter(w, wait)
		s.errorPage(w, r, http.StatusTooManyRequests, "Too many fingerprint fetches in a short time. "+tryAgainIn(wait))
		return false
	}
	return true
}

func (s *server) auditFetch(r *http.Request, sess session, serverID string, ap netip.AddrPort, kind string, err error) {
	e := audit.Entry{Principal: sess.id.User.Username, Role: string(sess.id.User.Role), ServerID: serverID,
		Action: ActionServerFingerprint, Result: audit.ResultOK,
		Params: map[string]any{"address": ap.Addr().String(), "port": int(ap.Port()), "kind": kind}}
	var te *tofu.Error
	if errors.As(err, &te) {
		e.Result, e.ErrorClass = audit.ResultError, string(te.Class)
	} else if err != nil {
		e.Result, e.ErrorClass = audit.ResultError, "error"
	}
	_ = s.record(r, e)
}

func fetchMessage(err error) string {
	var te *tofu.Error
	if errors.As(err, &te) {
		return "Fingerprint not fetched: " + te.Message()
	}
	return "Fingerprint not fetched."
}

func proofMessage(err error) string {
	if errors.Is(err, tofu.ErrProofExpired) {
		return "The fetched fingerprint is more than 5 minutes old. Fetch it again."
	}
	return "The fingerprint could not be confirmed (it was not the one fetched for this session). Fetch it again."
}

// claim binds a proof to this session, the confirming form's path (which names the
// action and the server), the kind, the address, the port and the value.
func (s *server) claim(sess session, purpose string, kind tofu.Kind, ap netip.AddrPort, value string) tofu.Claim {
	return tofu.Claim{Session: sessionBinding(sess.token), Purpose: purpose, Kind: kind, Addr: ap.Addr().String(),
		Port: int(ap.Port()), Value: value}
}

// normalisePin accepts 64 hex digits, with optional colons or spaces (as BMC pages
// print them), and returns the lower-case form.
func normalisePin(raw string) (string, bool) {
	if !pinFormPattern.MatchString(raw) {
		return "", false
	}
	p := strings.ToLower(strings.NewReplacer(":", "", " ", "", "\t", "", "\n", "", "\r", "").Replace(raw))
	return p, len(p) == 64
}

func splitTags(raw string) []string {
	var out []string
	for _, t := range tagSplitPattern.Split(strings.TrimSpace(raw), -1) {
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// invalidServerField names the form field a validation message is about.
func invalidServerField(msg string) string {
	for _, k := range []string{"name", "tags", "id", "bmc.address", "bmc.port", "bmc.kind", "tls_pin_sha256"} {
		if strings.Contains(msg, ": "+k) || strings.Contains(msg, k+" ") {
			return strings.TrimPrefix(strings.TrimSuffix(k, "_sha256"), "bmc.")
		}
	}
	return ""
}

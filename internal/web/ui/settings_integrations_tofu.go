package ui

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"oob-manager/internal/audit"
	"oob-manager/internal/config"
	"oob-manager/internal/integrations"
	"oob-manager/internal/settings"
	"oob-manager/internal/tofu"
)

// gelfTOFUView is the confirm page of a fetched log server certificate: the leaf and,
// when the server sent its chain, the issuer, each with its own proof; the admin picks
// which one to pin (default: the issuer when present, else the leaf).
type gelfTOFUView struct {
	Endpoint string
	Choices  []pinChoice
	Hidden   []kv
	CSRF     string
	Rev      int64
	StepUp   stepUpNote
	NoChain  bool
	// ShippingOn: the confirmed values turn shipping on (else the pin is only saved).
	ShippingOn bool
	// IssuerNote explains why a CA the server sent cannot be pinned ("" when it can, or
	// none was sent); PublicCA warns that the offered CA is publicly trusted.
	IssuerNote string
	PublicCA   bool
}

// pinChoice is one pinnable certificate.
type pinChoice struct {
	Kind     string // "leaf" or "issuer"
	Title    string
	Grouped  string
	Value    string
	Proof    string
	Facts    []kv
	Selected bool
}

// gelfClaim binds a proof to this session, the confirm path, the address as typed and
// the value.
func (s *server) gelfClaim(sess session, host string, port int, value string) tofu.Claim {
	return tofu.Claim{Session: sessionBinding(sess.token), Purpose: pathGELFPin, Kind: tofu.KindTLS, Addr: host,
		Port: port, Value: value}
}

// fetchGELFPin fetches the log server's certificate at the address typed in the form
// (handshake only, after the destination policy) and shows the confirm page carrying
// every other form value.
func (s *server) fetchGELFPin(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	if !s.integrationsBackend(w, r) {
		return
	}
	if s.d.Settings.Current().IntegrationsLocked {
		s.deny(r, sess, integrations.ActionFingerprint, "locked")
		s.errorPage(w, r, http.StatusForbidden, "The Integrations section is locked by settings.locked in config.yaml. Nothing was fetched.")
		return
	}
	submitted := gelfForm(form)
	addr := strings.TrimSpace(form.Get(config.KeyGELFAddress))
	if addr == "" {
		addr = s.d.Settings.Current().Integrations.Address
	}
	host, port, ok := splitHostPort(addr)
	if !ok {
		s.renderIntegrations(w, r, sess, http.StatusUnprocessableEntity, submitted,
			"Enter the log server's address as host:port before fetching its certificate.", config.KeyGELFAddress)
		return
	}
	if ok, wait := s.fpLimit.allow("user:" + sess.id.User.ID); !ok {
		s.deny(r, sess, integrations.ActionFingerprint, "rate_limited")
		setRetryAfter(w, wait)
		s.errorPage(w, r, http.StatusTooManyRequests, "Too many fingerprint fetches in a short time. "+tryAgainIn(wait))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), integrations.FetchTimeout)
	defer cancel()
	info, err := s.d.Integrations.Fingerprint(ctx, actor(r, sess), addr, strings.TrimSpace(form.Get(config.KeyGELFServerName)))
	if err != nil {
		s.renderIntegrations(w, r, sess, http.StatusUnprocessableEntity, submitted, gelfFetchMessage(err), config.KeyGELFAddress)
		return
	}
	s.renderGELFTOFU(w, r, sess, form, host, port, info)
}

func (s *server) renderGELFTOFU(w http.ResponseWriter, r *http.Request, sess session, form url.Values, host string,
	port int, info tofu.CertInfo) {
	rev, _ := strconv.ParseInt(form.Get("rev"), 10, 64)
	v := gelfTOFUView{Endpoint: net.JoinHostPort(host, strconv.Itoa(port)), CSRF: s.csrf.issue(formSettings, sessionBinding(sess.token)),
		Rev: rev, StepUp: s.stepUpNoteFor(r, sess), NoChain: !info.IssuerVerified, IssuerNote: issuerNote(info), PublicCA: info.IssuerVerified && info.IssuerPublic}
	v.ShippingOn = form.Get(config.KeyGELFEnabled) == "on" || (form.Get(config.KeyGELFEnabled) == "" && s.d.Settings.Current().Integrations.Enabled)
	v.StepUp.Next = pathIntegrations
	leaf := pinChoice{Kind: "leaf", Title: "The log server's own certificate (leaf)", Grouped: info.Grouped(), Value: info.SPKI,
		Facts: certFacts(sess, info), Selected: info.Recommended() == info.SPKI}
	leaf.Proof = s.d.Proofs.Sign(s.gelfClaim(sess, host, port, leaf.Value))
	v.Choices = append(v.Choices, leaf)
	if info.IssuerVerified {
		iss := info.Chain[0]
		c := pinChoice{Kind: "issuer", Title: "The CA that issued it (issuer)", Grouped: iss.Grouped(), Value: iss.SPKI,
			Facts: certFacts(sess, iss), Selected: info.Recommended() == iss.SPKI}
		c.Proof = s.d.Proofs.Sign(s.gelfClaim(sess, host, port, c.Value))
		v.Choices = append(v.Choices, c)
	}
	for _, k := range []string{config.KeyGELFEnabled, config.KeyGELFAddress, config.KeyGELFServerName} {
		if vals, ok := form[k]; ok && len(vals) == 1 {
			v.Hidden = append(v.Hidden, kv{k, vals[0]})
		}
	}
	noStore(w)
	d := s.settingsLayout(r, sess, "Confirm the log server certificate", v)
	d.Crumbs = []crumb{{"Settings", "/settings"}, {"Integrations", pathIntegrations}, {Label: "Confirm certificate"}}
	s.render(w, r, http.StatusOK, pageSettingsGELFTOFU, d)
}

// confirmGELFPin saves the chosen fetched pin (its proof must match this session, the
// address and the value) together with the carried form values, switches the transport
// to TLS and applies it. Audited as pin_via fetched with the certificate pinned.
func (s *server) confirmGELFPin(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	if !s.integrationsBackend(w, r) {
		return
	}
	pinned := form.Get("pinned")
	if pinned != "leaf" && pinned != "issuer" {
		s.renderIntegrations(w, r, sess, http.StatusUnprocessableEntity, nil, "Choose which certificate to pin.", "")
		return
	}
	submitted := gelfForm(form)
	addr := strings.TrimSpace(form.Get(config.KeyGELFAddress))
	if addr == "" {
		addr = s.d.Settings.Current().Integrations.Address
	}
	host, port, ok := splitHostPort(addr)
	value := form.Get("value_" + pinned)
	if !ok || s.d.Proofs.Verify(s.gelfClaim(sess, host, port, value), form.Get("proof_"+pinned)) != nil {
		s.renderIntegrations(w, r, sess, http.StatusUnprocessableEntity, submitted,
			"The fingerprint could not be confirmed (it was not the one fetched for this session and address, or it is more than 5 minutes old). Fetch it again.", "")
		return
	}
	submitted[config.KeyGELFPin], submitted[config.KeyGELFTransport] = value, config.TransportTLS
	rev, err := strconv.ParseInt(form.Get("rev"), 10, 64)
	if err != nil {
		s.renderIntegrations(w, r, sess, http.StatusBadRequest, nil, "The form could not be read. Reload the page.", "")
		return
	}
	changes, err := s.d.Integrations.Update(r.Context(), actor(r, sess), rev, submitted,
		settings.PinOrigin{Via: "fetched", Pinned: pinned})
	s.integrationsResult(w, r, sess, submitted, changes, err, "pinned")
}

// testGELF sends one test frame now (3 a minute per user) and reports the class.
func (s *server) testGELF(w http.ResponseWriter, r *http.Request, sess session, _ url.Values) {
	if !s.integrationsBackend(w, r) {
		return
	}
	if ok, wait := s.gelfTestLimit.allow("user:" + sess.id.User.ID); !ok {
		s.deny(r, sess, integrations.ActionTest, "rate_limited")
		setRetryAfter(w, wait)
		s.errorPage(w, r, http.StatusTooManyRequests, "Three tests a minute at most. "+tryAgainIn(wait))
		return
	}
	res := s.d.Integrations.SendTest(r.Context(), actor(r, sess))
	if res.OK {
		http.Redirect(w, r, pathIntegrations+"?done=test-ok", http.StatusSeeOther)
		return
	}
	class := res.Class
	if gelfClassText(class) == "" {
		class = audit.ClassDial
	}
	redirectLocal(w, r, pathIntegrations+"?done=test-failed-"+class)
}

func splitHostPort(addr string) (string, int, bool) {
	host, p, err := net.SplitHostPort(addr)
	port, perr := strconv.Atoi(p)
	if err != nil || perr != nil || host == "" || port < 1 || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}

func gelfFetchMessage(err error) string {
	var pe *integrations.PolicyError
	if errors.As(err, &pe) {
		return "Certificate not fetched: " + pe.Reason + "."
	}
	return fetchMessage(err)
}

// issuerNote says why the CA the server sent is not offered for pinning.
func issuerNote(info tofu.CertInfo) string {
	switch info.IssuerProblem {
	case tofu.IssuerUnrelated:
		return "The server also sent a CA certificate that did not issue its own certificate. Only the server's own certificate can be pinned; check the log server's TLS configuration."
	case tofu.IssuerWrongName:
		return "The server's certificate is not issued for this address. To pin its CA, set Server name to a name the certificate carries; otherwise pin the certificate itself."
	default:
		return ""
	}
}

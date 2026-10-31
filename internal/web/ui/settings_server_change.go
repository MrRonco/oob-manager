package ui

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmc/bmcssh"
	"oob-manager/internal/config"
	"oob-manager/internal/registry"
	"oob-manager/internal/secrets/credstore"
	"oob-manager/internal/tofu"
)

// Limits of the free-text feature fields.
const maxImpactText = 2048

// entryFor is the editable database entry of the request's server and the form's
// revision; on failure the response is written.
func (s *server) entryFor(w http.ResponseWriter, r *http.Request, sess session, form url.Values) (registry.Entry, int64, bool) {
	id := r.PathValue("id")
	x, ok := s.d.Servers.Current().Entry(id)
	if !ok || !serverIDPattern.MatchString(id) {
		s.errorPage(w, r, http.StatusNotFound, "There is no such server.")
		return registry.Entry{}, 0, false
	}
	rev, err := strconv.ParseInt(form.Get("rev"), 10, 64)
	if err != nil {
		s.renderServerEdit(w, r, sess, http.StatusBadRequest, "The form could not be read. Reload the page.")
		return registry.Entry{}, 0, false
	}
	return x, rev, true
}

// done redirects after a change, or reports the refusal on the server page.
func (s *server) done(w http.ResponseWriter, r *http.Request, sess session, changes []registry.Change, err error, key, anchor string) {
	if err != nil {
		status, msg := s.serverError(err)
		if status == http.StatusNotFound || status == http.StatusInternalServerError {
			s.errorPage(w, r, status, msg)
			return
		}
		s.renderServerEdit(w, r, sess, status, msg)
		return
	}
	if changes == nil {
		key = "server-unchanged"
	}
	redirectLocal(w, r, "/settings/servers/"+r.PathValue("id")+"?done="+key+"#"+anchor)
}

func (s *server) saveIdentity(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	x, rev, ok := s.entryFor(w, r, sess, form)
	if !ok {
		return
	}
	ch, err := s.d.Servers.UpdateIdentity(r.Context(), actor(r, sess), x.Server.ID, rev,
		strings.TrimSpace(form.Get("name")), splitTags(form.Get("tags")))
	s.done(w, r, sess, ch, err, "server-saved", "connection")
}

// connectionFingerprint fetches the HTTPS fingerprint of a new address (a move).
func (s *server) connectionFingerprint(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	x, rev, ok := s.entryFor(w, r, sess, form)
	if !ok {
		return
	}
	kind, address, port := form.Get("kind"), strings.TrimSpace(form.Get("address")), strings.TrimSpace(form.Get("port"))
	ap, msg, _ := s.target(kind, address, port)
	if msg != "" {
		s.renderServerEdit(w, r, sess, http.StatusUnprocessableEntity, msg)
		return
	}
	if pin := strings.TrimSpace(form.Get("pin")); pin != "" {
		if s.allowChange(w, r, sess, authz.AdminServersManage) {
			s.moveTo(w, r, sess, x, rev, ap, kind, pin, "manual")
		}
		return
	}
	info, err := s.fetchTLS(w, r, sess, ap, false, x.Server.ID)
	if err != nil {
		if !errors.Is(err, errRateLimited) {
			s.renderServerEdit(w, r, sess, http.StatusUnprocessableEntity, fetchMessage(err))
		}
		return
	}
	hidden := []kv{{"rev", strconv.FormatInt(rev, 10)}, {"kind", kind}, {"address", address}, {"port", port}}
	s.renderTOFU(w, r, sess, tofuView{Purpose: "Move " + x.Server.Name + " to " + ap.String(),
		Action: "/settings/servers/" + x.Server.ID + "/connection", Cancel: "/settings/servers/" + x.Server.ID,
		Hidden: hidden, Button: "Confirm fingerprint and move the server"}, tofu.KindTLS, ap, info.SPKI, certFacts(sess, info))
}

func (s *server) saveConnection(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	x, rev, ok := s.entryFor(w, r, sess, form)
	if !ok {
		return
	}
	kind := form.Get("kind")
	ap, msg, _ := s.target(kind, form.Get("address"), form.Get("port"))
	if msg != "" {
		s.renderServerEdit(w, r, sess, http.StatusUnprocessableEntity, msg)
		return
	}
	value := form.Get("value")
	if err := s.d.Proofs.Verify(s.claim(sess, r.URL.Path, tofu.KindTLS, ap, value), form.Get("proof")); err != nil {
		s.renderServerEdit(w, r, sess, http.StatusUnprocessableEntity, proofMessage(err))
		return
	}
	s.moveTo(w, r, sess, x, rev, ap, kind, value, "tofu")
}

func (s *server) moveTo(w http.ResponseWriter, r *http.Request, sess session, x registry.Entry, rev int64,
	ap netip.AddrPort, kind, pin, via string) {
	norm, ok := normalisePin(pin)
	if !ok {
		s.renderServerEdit(w, r, sess, http.StatusUnprocessableEntity, "The fingerprint must be 64 hexadecimal digits.")
		return
	}
	c := registry.Connection{Kind: config.BMCKind(kind), Address: ap.Addr().String(), Port: int(ap.Port()), TLSPin: norm, PinVia: via}
	ch, err := s.d.Servers.UpdateConnection(r.Context(), actor(r, sess), x.Server.ID, rev, c)
	s.done(w, r, sess, ch, err, "server-moved", "connection")
}

// pinEndpoint is where kind's fingerprint is fetched for server x, and its options.
func pinEndpoint(x registry.Entry, kind string) (netip.AddrPort, tofu.Kind, bool, bool) {
	s := x.Server
	port, k, rsa, legacy := s.BMC.Port, tofu.KindTLS, false, false
	switch kind {
	case "vnc":
		port, k, rsa = s.Console.VNC.Port, tofu.KindVNC, s.Console.VNC.Has(config.QuirkIDRAC8RSAKexTLS)
	case "ssh":
		port, k, legacy = s.Console.SSH.Port, tofu.KindSSH, s.Console.SSH.Has(config.QuirkIDRAC8LegacySSH)
	}
	addr, err := netip.ParseAddr(s.BMC.Address)
	if err != nil {
		return netip.AddrPort{}, k, false, false
	}
	return netip.AddrPortFrom(addr, uint16(port)), k, rsa, legacy //nolint:gosec // validated port
}

// pinFingerprint fetches a fingerprint of the server's current address (a new or
// changed certificate or host key: TOFU again, credentials are kept).
func (s *server) pinFingerprint(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	x, rev, ok := s.entryFor(w, r, sess, form)
	if !ok {
		return
	}
	kind := form.Get("kind")
	ap, k, rsa, legacy := pinEndpoint(x, kind)
	if !ap.IsValid() || (kind != "tls" && kind != "vnc" && kind != "ssh") {
		s.renderServerEdit(w, r, sess, http.StatusBadRequest, "Unknown fingerprint.")
		return
	}
	v := tofuView{Purpose: "Fingerprint of " + x.Server.Name, Action: "/settings/servers/" + x.Server.ID + "/pin",
		Cancel: "/settings/servers/" + x.Server.ID, Button: "Confirm fingerprint",
		Hidden: []kv{{"rev", strconv.FormatInt(rev, 10)}, {"kind", kind}}}
	if k == tofu.KindSSH {
		s.fetchSSHPin(w, r, sess, x, v, ap, legacy)
		return
	}
	info, err := s.fetchTLS(w, r, sess, ap, rsa, x.Server.ID)
	if err != nil {
		if !errors.Is(err, errRateLimited) {
			s.renderServerEdit(w, r, sess, http.StatusUnprocessableEntity, fetchMessage(err))
		}
		return
	}
	s.renderTOFU(w, r, sess, v, k, ap, info.SPKI, certFacts(sess, info))
}

func (s *server) fetchSSHPin(w http.ResponseWriter, r *http.Request, sess session, x registry.Entry, v tofuView,
	ap netip.AddrPort, legacy bool) {
	if !s.allowFingerprint(w, r, sess) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*tofu.DefaultDialTimeout+tofu.DefaultHandshakeTimeout)
	defer cancel()
	key, err := s.d.Prober.FetchSSH(ctx, ap, legacy)
	s.auditFetch(r, sess, x.Server.ID, ap, "ssh", err)
	if err != nil {
		s.renderServerEdit(w, r, sess, http.StatusUnprocessableEntity, fetchMessage(err))
		return
	}
	s.renderTOFU(w, r, sess, v, tofu.KindSSH, ap, key.Line, hostKeyFacts(key))
}

// savePin stores a fingerprint: fetched (with its proof) or pasted ("manual").
func (s *server) savePin(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	x, rev, ok := s.entryFor(w, r, sess, form)
	if !ok {
		return
	}
	kind, value, via := form.Get("kind"), strings.TrimSpace(form.Get("value")), "manual"
	ap, k, _, _ := pinEndpoint(x, kind)
	if proof := form.Get("proof"); proof != "" {
		if err := s.d.Proofs.Verify(s.claim(sess, r.URL.Path, k, ap, value), proof); err != nil {
			s.renderServerEdit(w, r, sess, http.StatusUnprocessableEntity, proofMessage(err))
			return
		}
		via = "tofu"
	}
	norm, msg := pinValue(kind, value)
	if msg != "" {
		s.renderServerEdit(w, r, sess, http.StatusUnprocessableEntity, msg)
		return
	}
	ch, err := s.d.Servers.SetPin(r.Context(), actor(r, sess), x.Server.ID, rev, kind, norm, via)
	s.done(w, r, sess, ch, err, "server-pin", "fingerprints")
}

// pinValue normalises a pasted value: SPKI hex for tls and vnc ("" = same as HTTPS for
// vnc), an authorized-key line for ssh.
func pinValue(kind, value string) (string, string) {
	switch {
	case kind == "ssh":
		if _, err := bmcssh.ParseHostKey(value); err != nil || len(value) > 2048 {
			return "", "Paste the host key as one line: type and key, for example ssh-ed25519 AAAA…"
		}
		return strings.Join(strings.Fields(value)[:2], " "), ""
	case kind == "vnc" && value == "":
		return "", ""
	default:
		p, ok := normalisePin(value)
		if !ok {
			return "", "The fingerprint must be 64 hexadecimal digits."
		}
		return p, ""
	}
}

// saveCredential replaces one stored credential. The password is never shown again,
// never put back into a form and never logged.
func (s *server) saveCredential(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	x, rev, ok := s.entryFor(w, r, sess, form)
	if !ok {
		return
	}
	slot, err := credstore.ParseSlot(r.PathValue("slot"))
	if err != nil {
		s.errorPage(w, r, http.StatusNotFound, "There is no such credential.")
		return
	}
	user, pass := strings.TrimSpace(form.Get("username")), form.Get("password")
	if len(user) > 64 || len(pass) > 256 || strings.ContainsAny(user, "\r\n\x00") {
		s.renderServerEdit(w, r, sess, http.StatusUnprocessableEntity, "Not saved: the username or password is too long.")
		return
	}
	if !slot.Login() {
		user = ""
	}
	ch, err := s.d.Servers.SetCredential(r.Context(), actor(r, sess), x.Server.ID, rev, slot, user, pass)
	s.done(w, r, sess, ch, err, "server-credential", "credentials")
}

// saveFeatures applies fans, consoles, power context and the poll interval.
func (s *server) saveFeatures(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	x, rev, ok := s.entryFor(w, r, sess, form)
	if !ok {
		return
	}
	f, msg := featuresFromForm(form)
	if msg != "" {
		s.renderServerEdit(w, r, sess, http.StatusUnprocessableEntity, msg)
		return
	}
	ch, err := s.d.Servers.UpdateFeatures(r.Context(), actor(r, sess), x.Server.ID, rev, f)
	s.done(w, r, sess, ch, err, "server-saved", "features")
}

func featuresFromForm(form url.Values) (registry.Features, string) {
	num := func(k string, def int) (int, bool) {
		v := strings.TrimSpace(form.Get(k))
		if v == "" {
			return def, true
		}
		if !digitsPattern.MatchString(v) {
			return 0, false
		}
		n, err := strconv.Atoi(v)
		return n, err == nil
	}
	safe, ok1 := num("safe_min_pct", 0)
	lease, ok2 := num("max_lease_min", 0)
	vnc, ok3 := num("vnc_port", config.DefaultVNCPort)
	sshPort, ok4 := num("ssh_port", config.DefaultSSHPort)
	poll, ok5 := num("poll_interval_s", 0)
	impact := strings.TrimSpace(strings.ReplaceAll(form.Get("impact"), "\r", ""))
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || len(impact) > maxImpactText {
		return registry.Features{}, "Not saved: numbers must be whole numbers, and the impact list at most 2048 characters."
	}
	var lines []string
	for _, l := range strings.Split(impact, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return registry.Features{FanMode: config.FanMode(form.Get("fan_mode")), FanSafeMin: safe,
		FanMaxLease: time.Duration(lease) * time.Minute, Serial: config.SerialKind(form.Get("serial")),
		Graphical: config.GraphicalKind(form.Get("graphical")), VNCPort: vnc, SSHPort: sshPort,
		SelfHost: form.Get("self_host") == "on", Impact: lines, PollInterval: time.Duration(poll) * time.Second}, ""
}

func (s *server) enableServer(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	x, rev, ok := s.entryFor(w, r, sess, form)
	if !ok {
		return
	}
	ch, err := s.d.Servers.SetEnabled(r.Context(), actor(r, sess), x.Server.ID, rev, true)
	s.done(w, r, sess, ch, err, "server-enabled", "review")
}

// testServer starts Test connection in the background (read-only; it can take a
// minute on a slow BMC); the server page refreshes until it finishes.
func (s *server) testServer(w http.ResponseWriter, r *http.Request, sess session, _ url.Values) {
	id := r.PathValue("id")
	if _, ok := s.d.Servers.Current().Entry(id); !ok {
		s.errorPage(w, r, http.StatusNotFound, "There is no such server.")
		return
	}
	if ok, wait := s.testLimit.allow("user:" + sess.id.User.ID); !ok {
		_ = s.record(r, audit.Entry{Principal: sess.id.User.Username, Role: string(sess.id.User.Role), ServerID: id,
			Action: "admin.server.test", Result: audit.ResultDenied, ErrorClass: "rate_limited"})
		setRetryAfter(w, wait)
		s.errorPage(w, r, http.StatusTooManyRequests, "Too many connection tests in a short time. "+tryAgainIn(wait))
		return
	}
	err := s.d.Prober.StartTest(id, sess.id.User.Username)
	if err != nil && !errors.Is(err, ErrTestRunning) {
		s.renderServerEdit(w, r, sess, http.StatusNotFound, "There is no such server.")
		return
	}
	redirectLocal(w, r, "/settings/servers/"+id+"?done=server-test#test")
}

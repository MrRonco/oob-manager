package ui

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"oob-manager/internal/audit"
	"oob-manager/internal/config"
	"oob-manager/internal/settings"
	"oob-manager/internal/tofu"
)

// integrationsView is Settings → Integrations (slice S4): audit shipping on the left,
// the copy-ready dashboard and monitoring hints on the right.
type integrationsView struct {
	StepUp    stepUpNote
	CSRF      string
	Rev       int64
	Locked    bool // settings.locked lists integrations: read-only, no buttons
	CanSave   bool
	FormError string
	State     gelfStateView
	Enabled   gelfField
	Address   gelfField
	Transport gelfField
	SNI       gelfField
	Pin       gelfField
	PinShown  string // the saved pin, grouped for reading ("" when none)
	Networks  string
	Queued    int // rows waiting: Save warns that they are sent now or dropped
	// PrevUnconfirmed: shipping is on but not connected, so the row recording a change
	// of destination may not reach the current one (Save warns).
	PrevUnconfirmed bool
	// Note explains saved values that are not in force (they no longer validate).
	Note  string
	Hints hintsView
}

// gelfField is one GELF key on the form.
type gelfField struct {
	Key, ID, Label, Help, Value string
	FileManaged, Invalid        bool
	Source                      string
	Resettable                  bool
}

// gelfStateView is the live state line and counters.
type gelfStateView struct {
	Status   healthView
	Lines    []kv
	Plain    bool // enabled over plain TCP: "unencrypted"
	Paused   bool
	ErrorMsg string
}

func (s *server) integrationsPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderIntegrations(w, r, sess, http.StatusOK, nil, "", "")
}

// renderIntegrations shows the page; submitted re-fills the form after a refusal and
// invalidKey marks the field the error is about.
func (s *server) renderIntegrations(w http.ResponseWriter, r *http.Request, sess session, status int,
	submitted map[string]string, formErr, invalidKey string) {
	cur := s.d.Settings.Current()
	st := s.d.Integrations.Stats()
	v := integrationsView{StepUp: s.stepUpNoteFor(r, sess), CSRF: s.csrf.issue(formSettings, sessionBinding(sess.token)),
		Rev: cur.Rev, Locked: cur.IntegrationsLocked, FormError: formErr, State: gelfState(st, s.d.Integrations.Applied(), sess.tf()),
		Queued: st.Queued, Networks: prefixList(s.d.Integrations.Networks()), Hints: s.hintsFor(r),
		PrevUnconfirmed: st.Active && !st.Connected, Note: cur.IntegrationsNote}
	v.StepUp.Next = pathIntegrations
	fields := map[string]*gelfField{config.KeyGELFEnabled: &v.Enabled, config.KeyGELFAddress: &v.Address,
		config.KeyGELFTransport: &v.Transport, config.KeyGELFServerName: &v.SNI, config.KeyGELFPin: &v.Pin}
	for _, f := range cur.IntegrationFields() {
		gf := gelfFieldOf(f, sess.tf(), cur.IntegrationsLocked)
		if val, ok := submitted[f.Key]; ok && !gf.FileManaged {
			gf.Value = val
		}
		gf.Invalid = f.Key == invalidKey
		v.CanSave = v.CanSave || !gf.FileManaged
		*fields[f.Key] = gf
	}
	if p := cur.Integrations.PinSHA256; p != "" {
		v.PinShown = tofu.CertInfo{SPKI: p}.Grouped()
	}
	v.Pin.Value = submitted[config.KeyGELFPin] // the paste box starts empty: blank keeps the pin
	s.render(w, r, status, pageSettingsIntegrations, s.integrationsLayout(r, sess, v))
}

func (s *server) integrationsLayout(r *http.Request, sess session, v integrationsView) layoutData {
	d := s.settingsLayout(r, sess, "Integrations", v)
	if msg, kind := integrationsDone(r.URL.Query().Get("done")); msg != "" {
		d.Flash, d.FlashKind = msg, kind
	}
	return d
}

func gelfFieldOf(f settings.Field, tf timeFmt, locked bool) gelfField {
	gf := gelfField{Key: f.Key, ID: "i-" + strings.NewReplacer(".", "-", "_", "-").Replace(f.Key), Label: f.Label,
		Help: f.Help, Value: f.Value, FileManaged: f.FileManaged() || locked}
	switch f.Source {
	case settings.SourceFile:
		gf.Source = "Set in config.yaml (" + config.FilePath(f.Key) + "). Edit the file and restart to change it."
	case settings.SourceDB:
		gf.Source = "Saved by " + f.UpdatedBy + " on " + tf.full(f.UpdatedAt) + "."
	default:
		gf.Source = "Default."
	}
	gf.Resettable = f.Source == settings.SourceDB && !gf.FileManaged
	return gf
}

// gelfState is the badge and counters of the running shipper.
func gelfState(st audit.ShipperStats, g config.GELF, tf timeFmt) gelfStateView {
	var v gelfStateView
	switch {
	case !st.Active:
		v.Status = healthView{Class: "stale", Label: "Disabled"}
		return v
	case st.PinMismatch:
		label := "Paused: certificate changed"
		if st.PauseReason == audit.ClassTLSExpired {
			label = "Paused: certificate expired"
		}
		v.Status, v.Paused = healthView{Class: "crit", Label: label}, true
	case st.Connected:
		v.Status = healthView{Class: "ok", Label: "Connected"}
	default:
		v.Status = healthView{Class: "warn", Label: "Disconnected"}
	}
	v.Plain = g.Transport != config.TransportTLS
	v.Lines = []kv{{"Destination", g.Address + " (" + transportLabel(g.Transport) + ")"},
		{"Queued", strconv.Itoa(st.Queued)}, {"Sent", formatCount(st.Sent)}, {"Dropped", formatCount(st.Dropped)},
		{"Reconnects", formatCount(st.Reconnects)}}
	if !st.ConnectedSince.IsZero() {
		v.Lines = append(v.Lines, kv{"Connected since", tf.full(st.ConnectedSince)})
	}
	if !st.LastSuccess.IsZero() {
		v.Lines = append(v.Lines, kv{"Last row sent", tf.full(st.LastSuccess)})
	}
	if st.LastError != "" {
		v.Lines = append(v.Lines, kv{"Last error", st.LastError})
		v.ErrorMsg = gelfClassText(st.LastError)
	}
	if st.PauseReason != "" { // the pause explains more than a later failed probe
		v.ErrorMsg = gelfClassText(st.PauseReason)
	}
	return v
}

func transportLabel(t string) string {
	if t == config.TransportTLS {
		return "TLS, pinned"
	}
	return "plain TCP, unencrypted"
}

// gelfClassText explains a failure class in a sentence (a closed set).
func gelfClassText(class string) string {
	return map[string]string{
		audit.ClassDial:       "The log server did not accept the connection. Check the address, the port and its GELF input.",
		audit.ClassTimeout:    "The log server did not answer in time.",
		audit.ClassTLS:        "The TLS handshake failed: the input may not have TLS enabled, or it is not a TLS port.",
		audit.ClassTLSPin:     "The log server's certificate does not match the pinned fingerprint. Shipping is paused; rows queue (up to 1,024, then dropped and counted). If the certificate was renewed on purpose, fetch and confirm the new fingerprint.",
		audit.ClassTLSExpired: "The log server's certificate comes from the pinned CA for the right name but has expired (or is not valid yet). Shipping is paused; rows queue. Renew it on the log server; shipping resumes on its own.",
		"audit":               "The audit row could not be written, so nothing was sent.",
		"policy":              "The address is not allowed (audit.gelf.allowed_networks, or a DNS answer outside it).",
		"dns":                 "The host name did not resolve.",
		audit.ClassWrite:      "The connection was lost while sending; the shipper reconnects.",
		audit.ClassOff:        "Audit shipping is disabled.",
		audit.ClassEncode:     "The test message could not be encoded.",
	}[class]
}

// saveIntegrations applies the form: only the fields the browser sent (disabled,
// file-managed inputs are not submitted); an empty pin box keeps the pin.
func (s *server) saveIntegrations(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	if !s.integrationsBackend(w, r) {
		return
	}
	submitted := gelfForm(form)
	rev, err := strconv.ParseInt(form.Get("rev"), 10, 64)
	if err != nil {
		s.renderIntegrations(w, r, sess, http.StatusBadRequest, submitted, "The form could not be read. Reload the page.", "")
		return
	}
	changes, err := s.d.Integrations.Update(r.Context(), actor(r, sess), rev, submitted, settings.PinOrigin{})
	s.integrationsResult(w, r, sess, submitted, changes, err, "saved")
}

// gelfForm collects the GELF keys present once in form; a blank pin box is dropped.
func gelfForm(form url.Values) map[string]string {
	out := map[string]string{}
	for _, k := range config.IntegrationKeys() {
		if vals, ok := form[k]; ok && len(vals) == 1 {
			out[k] = vals[0]
		}
	}
	if strings.TrimSpace(out[config.KeyGELFPin]) == "" {
		delete(out, config.KeyGELFPin)
	}
	return out
}

func (s *server) resetIntegrations(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	if !s.integrationsBackend(w, r) {
		return
	}
	rev, err := strconv.ParseInt(form.Get("rev"), 10, 64)
	if err != nil {
		s.renderIntegrations(w, r, sess, http.StatusBadRequest, nil, "The form could not be read. Reload the page.", "")
		return
	}
	changes, err := s.d.Integrations.Reset(r.Context(), actor(r, sess), rev, form.Get("reset"))
	s.integrationsResult(w, r, sess, nil, changes, err, "reset")
}

// integrationsResult maps a save or reset outcome to a redirect or an error page.
func (s *server) integrationsResult(w http.ResponseWriter, r *http.Request, sess session, submitted map[string]string,
	changes []settings.Change, err error, done string) {
	switch {
	case err == nil && len(changes) == 0:
		http.Redirect(w, r, pathIntegrations+"?done=unchanged", http.StatusSeeOther)
	case err == nil:
		http.Redirect(w, r, pathIntegrations+"?done="+done, http.StatusSeeOther)
	case errors.Is(err, settings.ErrConflict):
		s.renderIntegrations(w, r, sess, http.StatusConflict, nil, err.Error(), "")
	case errors.Is(err, settings.ErrLocked):
		s.errorPage(w, r, http.StatusForbidden, "This setting is managed by config.yaml or the Integrations section is locked. Nothing was changed.")
	case errors.Is(err, settings.ErrInvalid):
		s.renderIntegrations(w, r, sess, http.StatusUnprocessableEntity, submitted, generalErrorText(err), gelfInvalidKey(err))
	default:
		s.d.Logger.Error("ui integrations save failed", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "The settings could not be saved. Nothing was changed.")
	}
}

// gelfInvalidKey finds the key a validation message names ("audit.gelf.address" → gelf.address).
func gelfInvalidKey(err error) string {
	msg := err.Error()
	for _, k := range []string{config.KeyGELFPin, config.KeyGELFServerName, config.KeyGELFTransport, config.KeyGELFAddress} {
		if strings.Contains(msg, k) {
			return k
		}
	}
	if strings.Contains(msg, "ship audit rows") || strings.Contains(msg, "on or off") {
		return config.KeyGELFEnabled
	}
	return ""
}

// integrationsDone is the result message of ?done= (a closed set, nothing echoed).
func integrationsDone(key string) (string, string) {
	switch key {
	case "saved":
		return "Saved and applied without a restart.", "info"
	case "reset":
		return "Setting reset and applied.", "info"
	case "unchanged":
		return "Nothing changed.", "info"
	case "pinned":
		return "Fingerprint confirmed and applied. Shipping uses TLS with this pin from now on.", "info"
	case "test-ok":
		return "Test sent: the log server accepted the bytes. Check it for the message \"oob-manager GELF test\".", "info"
	}
	if c, ok := strings.CutPrefix(key, "test-failed-"); ok {
		if msg := gelfClassText(c); msg != "" {
			return "Test failed: " + msg, "error"
		}
	}
	return "", ""
}

package ui

import (
	"net/http"
	"net/netip"
	"strings"
	"unicode"

	"oob-manager/internal/tofu"
)

// tofuView is the "confirm this fingerprint" page (trust on first use): what was
// fetched, how to check it, and a form whose proof binds the value to this session.
type tofuView struct {
	Purpose  string // "Add server Edge one", "New HTTPS certificate of edge1"
	What     string // "HTTPS certificate", "VNC certificate", "SSH host key"
	Endpoint string // "192.0.2.12:443"
	Grouped  string // the fingerprint, grouped for reading
	Facts    []kv
	Hint     string
	Action   string
	Cancel   string
	Button   string
	Hidden   []kv
	Value    string
	Proof    string
	CSRF     string
	StepUp   stepUpNote
}

// renderTOFU renders the confirm page for value (an SPKI hex or a host key line)
// fetched from ap. It is a 200 with no-store (it carries a proof), never a redirect.
func (s *server) renderTOFU(w http.ResponseWriter, r *http.Request, sess session, v tofuView, kind tofu.Kind,
	ap netip.AddrPort, value string, facts []kv) {
	v.Endpoint, v.Value, v.Facts = ap.String(), value, facts
	v.Proof = s.d.Proofs.Sign(s.claim(sess, v.Action, kind, ap, value))
	v.CSRF = s.csrf.issue(formSettings, sessionBinding(sess.token))
	v.StepUp = s.stepUpNoteFor(r, sess)
	switch kind {
	case tofu.KindSSH:
		v.What = "SSH host key"
		v.Hint = "Compare the SHA256 fingerprint with the one the BMC shows on its own console, or with ssh-keygen -lf on a copy of its host key. Confirm only if they are identical."
		v.Grouped = factValue(facts, "Fingerprint")
	default:
		v.What = "HTTPS certificate"
		if kind == tofu.KindVNC {
			v.What = "VNC certificate"
		}
		v.Hint = "Compare this SHA-256 of the certificate's public key with the certificate page of the BMC's own web interface (or its local console). Confirm only if they are identical: from now on the console talks only to a BMC that holds this key."
		v.Grouped = tofu.CertInfo{SPKI: value}.Grouped()
	}
	noStore(w)
	d := s.settingsLayout(r, sess, "Confirm fingerprint", v)
	d.Crumbs = []crumb{{"Settings", "/settings"}, {"Servers", "/settings/servers"}, {Label: "Confirm fingerprint"}}
	s.render(w, r, http.StatusOK, pageSettingsServerTOFU, d)
}

func factValue(facts []kv, key string) string {
	for _, f := range facts {
		if f.Key == key {
			return f.Value
		}
	}
	return ""
}

// certFacts are the certificate fields an admin can compare. They are escaped by the
// template like any text.
func certFacts(sess session, c tofu.CertInfo) []kv {
	out := []kv{{"Subject", certText(c.Subject)}, {"Issuer", certText(c.Issuer)},
		{"Valid from", sess.tf().full(c.NotBefore)}, {"Valid until", sess.tf().full(c.NotAfter)}}
	if len(c.SANs) > 0 {
		out = append(out, kv{"Names", certText(strings.Join(c.SANs, ", "))})
	}
	return out
}

// maxCertText bounds each certificate field shown (a hostile BMC chooses them).
const maxCertText = 200

// certText strips control and bidirectional formatting characters (they could make
// the text read differently from what it is) and truncates.
func certText(s string) string {
	clean := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	if r := []rune(clean); len(r) > maxCertText {
		clean = string(r[:maxCertText]) + "…"
	}
	return nonBlank(clean)
}

func hostKeyFacts(k tofu.HostKey) []kv {
	return []kv{{"Fingerprint", k.Fingerprint}, {"Type", k.Type}}
}

func nonBlank(s string) string {
	if s == "" {
		return "(empty)"
	}
	return s
}

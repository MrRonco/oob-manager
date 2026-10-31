package ui

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"oob-manager/internal/bmc/bmcssh"
	"oob-manager/internal/config"
	"oob-manager/internal/registry"
	"oob-manager/internal/secrets/credstore"
	"oob-manager/internal/tofu"
)

// serverEditView is one server's settings page: the add/edit wizard's steps
// (connection → fingerprints → credentials → features → review and enable) as sections.
type serverEditView struct {
	StepUp      stepUpNote
	CSRF        string
	Rev         int64
	ID, Name    string
	Tags        string
	Kind        string
	KindLabel   string
	Kinds       []kindOption
	Address     string
	Port        string
	FileManaged bool // config.yaml: read-only, lock badge
	Locked      bool // settings.locked: [servers]
	Editable    bool
	Enabled     bool
	Shadowed    bool
	Status      healthView
	Steps       []wizardStep
	Problems    []string
	PinMismatch bool
	HostKeyBad  bool
	Pins        []pinView
	Creds       []credView
	Features    featureForm
	Test        *testView
	TestRunning bool
	FormError   string
}

type wizardStep struct {
	N             int
	Label, Anchor string
	Done, Current bool
}

type pinView struct {
	Kind, Label, Value, Note string
	Set, Needed              bool
	Fetchable                bool
	SameAllowed              bool // the VNC pin may be "same as HTTPS"
}

type credView struct {
	Slot, Label, Status, FileRef string
	Login, Set, Needed           bool
}

type featureForm struct {
	FanModes, Serials, Graphicals []option
	SafeMin, MaxLease             string
	VNCPort, SSHPort              string
	SelfHost                      bool
	Impact                        string
	PollInterval                  string
	FanFloorHint                  string
}

type testView struct {
	Summary string
	OK      bool
	Kind    string
	Steps   []TestStep
}

func (s *server) serverSettingsPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderServerEdit(w, r, sess, http.StatusOK, "")
}

// renderServerEdit shows server {id}; msg (with status) reports a refused change.
func (s *server) renderServerEdit(w http.ResponseWriter, r *http.Request, sess session, status int, msg string) {
	id := r.PathValue("id")
	eff := s.d.Servers.Current()
	x, ok := eff.Entry(id)
	if !ok {
		if x, ok = eff.DBEntry(id); !ok {
			s.errorPage(w, r, http.StatusNotFound, "There is no such server.")
			return
		}
	}
	v := s.serverEditOf(r, sess, eff, x)
	v.FormError = msg
	d := s.settingsLayout(r, sess, x.Server.Name, v)
	d.Crumbs = []crumb{{"Settings", "/settings"}, {"Servers", "/settings/servers"}, {Label: x.Server.Name}}
	if v.TestRunning && status == http.StatusOK {
		// The page holds typed forms: the script refresh pauses while one is edited, a
		// no-script meta refresh would wipe it (the panel says to reload instead).
		d.Refresh, d.RefreshScriptOnly = 5, true
	}
	s.render(w, r, status, pageSettingsServer, d)
}

func (s *server) serverEditOf(r *http.Request, sess session, eff registry.Effective, x registry.Entry) serverEditView {
	srv := x.Server
	v := serverEditView{StepUp: s.stepUpNoteFor(r, sess), CSRF: s.csrf.issue(formSettings, sessionBinding(sess.token)),
		Rev: x.Rev, ID: srv.ID, Name: srv.Name, Tags: strings.Join(srv.Tags, " "), Kind: string(srv.BMC.Kind),
		Kinds: kindOptions(string(srv.BMC.Kind)), Address: srv.BMC.Address, Port: strconv.Itoa(srv.BMC.Port),
		FileManaged: x.Source == registry.SourceFile, Locked: eff.Locked, Enabled: x.Enabled, Shadowed: x.Shadowed,
		Status: s.entryStatus(x), Problems: x.Problems}
	v.StepUp.Next = r.URL.Path
	v.KindLabel = kindLabel(v.Kind)
	v.Editable = !v.FileManaged && !v.Locked && !v.Shadowed
	if fv, ok := s.d.Fleet.Server(srv.ID); ok {
		v.PinMismatch = fv.PinMismatch
	}
	if s.d.Serial != nil {
		v.HostKeyBad = s.d.Serial.Status(srv.ID).Last.Class == "host_key"
	}
	v.Pins = pinsOf(srv)
	v.Creds = credsOf(x)
	v.Features = featuresOf(x)
	v.Steps = stepsOf(x, v.Pins, v.Creds)
	if t, ok := s.d.Prober.LastTest(srv.ID); ok {
		v.TestRunning = t.Running
		v.Test = &testView{Summary: testSummary(sess, t), OK: t.OK, Kind: string(t.Kind), Steps: t.Steps}
	}
	return v
}

func kindLabel(kind string) string {
	for _, k := range kindOptions("") {
		if k.Value == kind {
			return k.Label
		}
	}
	return kind
}

func pinsOf(s config.Server) []pinView {
	tls := pinView{Kind: "tls", Label: "HTTPS certificate (Redfish)", Value: tofu.CertInfo{SPKI: s.TLSPinSHA256}.Grouped(),
		Set: s.TLSPinSHA256 != "", Needed: true, Fetchable: true}
	out := []pinView{tls}
	if s.Console.Graphical == config.GraphicalVNC {
		vnc := pinView{Kind: "vnc", Label: "VNC certificate", Set: true, Needed: true, Fetchable: true, SameAllowed: true}
		if s.Console.VNC.PinSHA256 == "" {
			vnc.Note = "Same as the HTTPS certificate."
		} else {
			vnc.Value = tofu.CertInfo{SPKI: s.Console.VNC.PinSHA256}.Grouped()
		}
		out = append(out, vnc)
	}
	if s.Console.Serial == config.SerialBMCSSH {
		sshPin := pinView{Kind: "ssh", Label: "SSH host key (serial console)", Set: s.SSHHostKey != "", Needed: true, Fetchable: true}
		if key, err := bmcssh.ParseHostKey(s.SSHHostKey); err == nil {
			sshPin.Value = ssh.FingerprintSHA256(key) + " (" + key.Type() + ")"
		}
		out = append(out, sshPin)
	}
	return out
}

func credsOf(x registry.Entry) []credView {
	s := x.Server
	refs := map[credstore.Slot]string{credstore.SlotReadOnly: s.Credentials.ReadOnly,
		credstore.SlotOperator: s.Credentials.Operator, credstore.SlotVNC: s.Credentials.VNC}
	needOp := s.Fan.Mode == config.FanRedfishFloor || s.Fan.Mode == config.FanIPMIOEM ||
		s.Console.Serial != config.SerialNone || s.Console.Graphical == config.GraphicalKVMLaunch
	needed := map[credstore.Slot]bool{credstore.SlotReadOnly: true, credstore.SlotOperator: needOp,
		credstore.SlotVNC: s.Console.Graphical == config.GraphicalVNC}
	var out []credView
	for _, slot := range credstore.Slots() {
		c := credView{Slot: string(slot), Label: slot.Label(), Login: slot.Login(), Needed: needed[slot], Status: "Not set"}
		if x.Source == registry.SourceFile {
			c.FileRef, c.Set = refs[slot], refs[slot] != ""
			if c.Set {
				c.Status = "From the age file (" + refs[slot] + ")"
			}
		} else if ci, ok := x.Cred(slot); ok {
			c.Set = true
			c.Status = fmt.Sprintf("Set · v%d · %s by %s", ci.Version, ci.CreatedAt.UTC().Format("2006-01-02"), ci.CreatedBy)
		}
		out = append(out, c)
	}
	return out
}

func featuresOf(x registry.Entry) featureForm {
	s := x.Server
	dell := s.BMC.Kind == config.KindIDRAC8 || s.BMC.Kind == config.KindIDRAC9
	f := featureForm{VNCPort: strconv.Itoa(s.Console.VNC.Port), SSHPort: strconv.Itoa(s.Console.SSH.Port),
		SelfHost: s.Power.SelfHost, Impact: strings.Join(s.Power.Impact, "\n")}
	fans := []option{{Value: "none", Label: "None: the BMC's own fan curve"}}
	switch s.BMC.Kind {
	case config.KindIDRAC8:
		fans = append(fans, option{Value: "host-lease", Label: "Host lease file (host fan script)"})
		f.FanFloorHint = "Floor 30 to 100 %; lease up to 120 minutes."
	case config.KindIDRAC9:
		fans = append(fans, option{Value: "redfish-floor", Label: "BMC minimum fan speed (needs the operator login)"})
		f.FanFloorHint = "Floor 35 to 100 %; lease up to 120 minutes."
	}
	f.FanModes = selectOpt(fans, string(s.Fan.Mode))
	serials := []option{{Value: "none", Label: "None"}}
	if dell {
		serials = append(serials, option{Value: "bmcssh", Label: "BMC SSH (console com2, operator login)"})
	}
	f.Serials = selectOpt(serials, string(s.Console.Serial))
	graphicals := []option{{Value: "none", Label: "None"}, {Value: "vnc", Label: "VNC in the browser (VNC password)"}}
	if s.BMC.Kind == config.KindIDRAC9 {
		graphicals = append(graphicals, option{Value: "kvm-launch", Label: "Native iDRAC9 console launch (operator login)"})
	}
	graphicals = append(graphicals, option{Value: "link", Label: "Link to the BMC web interface only"})
	f.Graphicals = selectOpt(graphicals, string(s.Console.Graphical))
	if s.Fan.Mode != config.FanNone {
		f.SafeMin, f.MaxLease = strconv.Itoa(s.Fan.SafeMinPct), strconv.Itoa(int(s.Fan.MaxLease.Minutes()))
	}
	if x.PollInterval > 0 {
		f.PollInterval = strconv.Itoa(int(x.PollInterval.Seconds()))
	}
	return f
}

func selectOpt(opts []option, cur string) []option {
	for i := range opts {
		opts[i].Selected = opts[i].Value == cur
	}
	return opts
}

func stepsOf(x registry.Entry, pins []pinView, creds []credView) []wizardStep {
	pinsDone, credsDone := true, true
	for _, p := range pins {
		pinsDone = pinsDone && (p.Set || !p.Needed)
	}
	for _, c := range creds {
		credsDone = credsDone && (c.Set || !c.Needed)
	}
	steps := []wizardStep{{1, "Connection", "connection", true, false}, {2, "Fingerprints", "fingerprints", pinsDone, false},
		{3, "Credentials", "credentials", credsDone, false}, {4, "Features", "features", true, false},
		{5, "Review and enable", "review", x.Enabled || x.Source == registry.SourceFile, false}}
	for i := range steps {
		if !steps[i].Done {
			steps[i].Current = true
			break
		}
	}
	return steps
}

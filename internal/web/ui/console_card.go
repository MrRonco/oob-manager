package ui

import (
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/console"
)

// cardState is the graphical console card's state (docs/research/console.md §4.4).
type cardState string

const (
	cardReady       cardState = "ready"
	cardInUse       cardState = "in-use"
	cardSetup       cardState = "setup"
	cardLicense     cardState = "license"
	cardUnsupported cardState = "unsupported"
	cardUnknown     cardState = "unknown"
)

// consoleCard is the server page's "Graphical console" card.
type consoleCard struct {
	ID          string
	State       cardState
	Title       string
	Message     string
	Steps       []string
	Warnings    []string
	OpenVNC     bool   // the VNC console can be opened
	KVM         bool   // the BMC's native console can be launched
	KVMNote     string // why a native launch the BMC supports is not offered
	TLS         bool
	ActiveUser  string
	ActiveSince string
	ActiveISO   string
	BMCURL      string
	Allowed     bool // the viewer's role may use the console
	KVMCSRF     string
	Version     string
}

type cardInput struct {
	kvm bool
	tf  timeFmt
}

var setupSteps = []string{
	"On the BMC (iDRAC: iDRAC Settings → Services → VNC Server): enable the VNC server, keep port 5901, turn SSL encryption on and set an 8-character password with upper and lower case letters, a digit and a special character.",
	"Add that password to the credentials file as a password-only entry and reference it as credentials.vnc.",
	"Set console.graphical: vnc for the server (console.vnc.tls must match the BMC's SSL setting) and restart oob-manager.",
}

// buildConsoleCard decides the card from the console broker's status and what the
// poller learned about the BMC (Redfish GraphicalConsole, licence, KVM launch action).
func buildConsoleCard(v ServerView, st console.Status, in cardInput) consoleCard {
	c := consoleCard{ID: v.ID, KVM: in.kvm, TLS: st.TLS, Warnings: st.Warnings}
	f := v.Capabilities.Flags()
	switch {
	case licenseTooLow(v):
		return c.with(cardLicense, "Needs a higher BMC license",
			"This BMC's license does not include the virtual console (iDRAC needs Enterprise or Datacenter). Use the serial console.")
	case st.Configured:
		return configuredCard(c, st, in.tf)
	case in.kvm:
		c = c.with(cardReady, "Native console available",
			"This BMC can open its own HTML5 console with a one-time login. The in-app VNC console is not configured.")
		return c
	case !v.HasCapabilities:
		return c.with(cardUnknown, "Not checked yet", "Support is determined after the first full poll of the BMC.")
	case !f.GraphicalConsole:
		return c.with(cardUnsupported, "Not supported",
			"Graphical console not supported on this BMC — use the serial console.")
	default:
		c = c.with(cardSetup, "Needs setup", "The BMC offers a virtual console, but the VNC console is not set up in oob-manager.")
		c.Steps = setupSteps
		return c
	}
}

func licenseTooLow(v ServerView) bool {
	if !v.HasInventory {
		return false
	}
	t := v.Inventory.License().Tier
	return t == bmc.LicenseBasic || t == bmc.LicenseExpress
}

func configuredCard(c consoleCard, st console.Status, tf timeFmt) consoleCard {
	switch {
	case st.InUse:
		c = c.with(cardInUse, "In use", "Another graphical console session is open on this server.")
		c.ActiveUser, c.ActiveSince = st.Active.Username, tf.full(st.Active.Since)
		c.ActiveISO = st.Active.Since.UTC().Format(time.RFC3339)
		return c
	case !st.HasPassword:
		c = c.with(cardSetup, "Needs setup", "No VNC password is stored for this server (the credentials.vnc entry is missing).")
	case !st.RejectedAt.IsZero():
		c = c.with(cardSetup, "Needs setup", "The BMC rejected the stored VNC password. Set the same password on the BMC and in the credentials file.")
	default:
		if msg := probeProblem(st.Probe.State); msg != "" {
			c = c.with(cardSetup, "Needs setup", msg)
		} else {
			c = c.with(cardReady, "Ready", "Opens the BMC's screen, keyboard and mouse in this browser (equivalent to physical access).")
			c.OpenVNC = true
			return c
		}
	}
	c.Steps = setupSteps
	return c
}

func probeProblem(p console.ProbeState) string {
	switch p {
	case console.ProbeRefused:
		return "Nothing answers on the BMC's VNC port: the VNC server is probably disabled on the BMC."
	case console.ProbePin:
		return "The VNC port's certificate does not match the configured pin (console.vnc.tls_pin_sha256 or tls_pin_sha256)."
	case console.ProbeTLS:
		return "The TLS handshake on the VNC port failed: check that console.vnc.tls matches the BMC's VNC SSL setting."
	case console.ProbeNotRFB:
		return "Something other than a VNC server answers on the configured port."
	case console.ProbeUnreached:
		return "The BMC's VNC port could not be reached."
	default:
		return ""
	}
}

func (c consoleCard) with(s cardState, title, msg string) consoleCard {
	c.State, c.Title, c.Message = s, title, msg
	return c
}

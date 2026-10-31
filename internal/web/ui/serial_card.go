package ui

import (
	"time"

	"oob-manager/internal/authz"
	"oob-manager/internal/console"
)

// serialCard is the server page's "Serial console" card (states: ready, in use, needs
// setup, unsupported, not checked yet).
type serialCard struct {
	ID          string
	State       cardState
	Title       string
	Message     string
	Steps       []string
	Warnings    []string
	Open        bool // the serial console can be opened now
	ActiveUser  string
	ActiveSince string
	ActiveISO   string
	BMCURL      string
	Allowed     bool // the viewer's role may use the serial console
}

var serialSetupSteps = []string{
	"On the BMC: enable SSH and serial over LAN (iDRAC: iDRAC Settings → Services → SSH, and iDRAC Settings → Connectivity → Serial Over LAN), and let the operator account use the serial console.",
	"Read the BMC's SSH host key over a trusted path and set it as ssh_host_key for the server (an exact match is required; the app never trusts a key on first use).",
	"Set console.serial: bmcssh and credentials.operator for the server (iDRAC8 also keeps the default console.ssh.quirks: [idrac8_legacy_ssh]), then restart oob-manager.",
	"On the host: turn on BIOS serial redirection to COM2 and a serial console in the operating system (deploy/README.md, \"Enabling the serial console\").",
}

// silentHint is shown with every usable card: a connected console that stays blank
// means the host does not write to the BMC's serial port.
const silentHint = "A console that connects but stays blank means the host is not using COM2: enable BIOS serial redirection and a serial console on the operating system."

// buildSerialCard decides the card from the serial broker's status and what the poller
// learned about the BMC (Redfish SerialConsole).
func buildSerialCard(v ServerView, st console.SerialStatus, tf timeFmt) serialCard {
	c := serialCard{ID: v.ID}
	if st.Legacy {
		c.Warnings = append(c.Warnings, "Legacy SSH algorithms are enabled for this BMC (idrac8_legacy_ssh): ssh-rsa host key signatures (SHA-1) and diffie-hellman-group14-sha1 key exchange.")
	}
	switch {
	case !st.Configured && !v.HasCapabilities:
		return c.with(cardUnknown, "Not checked yet", "Support is determined after the first full poll of the BMC.")
	case !st.Configured && !v.Capabilities.Flags().SerialConsole:
		return c.with(cardUnsupported, "Not supported", "This BMC does not report a serial console.")
	case !st.Configured:
		c = c.with(cardSetup, "Needs setup", "The BMC offers a serial console, but it is not set up in oob-manager.")
		c.Steps = serialSetupSteps
		return c
	case !st.Supported:
		return c.with(cardUnsupported, "Not supported yet",
			"IPMI Serial-over-LAN (console.serial: sol) is not implemented yet. Use the BMC web interface.")
	case st.InUse:
		c = c.with(cardInUse, "In use", "Another serial console session is open on this server.")
		c.ActiveUser, c.ActiveSince = st.Active.Username, tf.full(st.Active.Since)
		c.ActiveISO = st.Active.Since.UTC().Format(time.RFC3339)
		return c
	}
	if msg := serialProblem(st); msg != "" {
		c = c.with(cardSetup, "Needs setup", msg)
		c.Steps = serialSetupSteps
		return c
	}
	c = c.with(cardReady, "Ready", "Opens the host's text console (BIOS, boot loader, operating system login) through the BMC. Screen-reader friendly.")
	c.Open = true
	if st.Last.Class == "unreachable" || st.Last.Class == "timeout" {
		c.Warnings = append(c.Warnings, "The last connection attempt failed: the BMC's SSH service did not answer.")
	}
	c.Warnings = append(c.Warnings, silentHint)
	return c
}

// serialProblem explains what blocks a configured bmcssh console, "" when nothing does.
func serialProblem(st console.SerialStatus) string {
	switch {
	case !st.HasLogin:
		return "No operator login is stored for this server (the credentials.operator entry is missing from the credentials file)."
	case !st.HasHostKey:
		return "The BMC's SSH host key is not configured (ssh_host_key)."
	case !st.RejectedAt.IsZero() || st.Last.Class == "bmc_auth":
		return "The BMC rejected the operator login. Check the account and the password in the credentials file."
	case st.Last.Class == "host_key":
		return "The BMC's SSH host key does not match ssh_host_key. If the BMC was reset or its key regenerated, verify the new key over a trusted path before updating the config."
	case st.Last.Class == "algorithms":
		return "The BMC offers no SSH algorithm in common with oob-manager. An iDRAC8 needs console.ssh.quirks: [idrac8_legacy_ssh]."
	case st.Last.Class == "bmc_protocol":
		return "The BMC refused the serial console (console com2). Check that serial over LAN is enabled and that the operator account may use it."
	default:
		return ""
	}
}

func (c serialCard) with(s cardState, title, msg string) serialCard {
	c.State, c.Title, c.Message = s, title, msg
	return c
}

// serialCardFor builds the card for the signed-in principal.
func (s *server) serialCardFor(v ServerView, sess session) serialCard {
	c := buildSerialCard(v, s.d.Serial.Status(v.ID), sess.tf())
	c.Allowed = s.d.Authorize(sess.id.Principal(), authz.ConsoleSerial, true) == nil
	c.BMCURL = s.d.BMCWebURL(v.ID)
	return c
}

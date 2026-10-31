package bmc

import (
	"slices"
	"time"
)

// RedfishPosture is what the security checks read over Redfish (GETs only, with the
// read-only login). Standard DMTF resources come first; a vendor reader (Dell iDRAC
// attributes) fills in or overrides facts and names itself in each Fact.Source.
type RedfishPosture struct {
	Protocols ProtocolFacts
	Accounts  AccountFacts
	Clock     ClockFacts
	Firmware  FirmwareFacts
	Licenses  LicenseFacts
	Network   NetworkFacts
	// Attributes is how the vendor attribute document was read (Dell iDRAC
	// Manager attributes); ReadNotTried on BMCs without one.
	Attributes Section
}

// ProtocolFacts are the BMC's network services (ManagerNetworkProtocol and vendor
// attributes).
type ProtocolFacts struct {
	Read Section // ManagerNetworkProtocol

	IPMI         Fact[bool] // IPMI over LAN (UDP 623)
	Telnet       Fact[bool]
	SSH          Fact[bool]
	HTTP         Fact[bool] // plain HTTP
	HTTPS        Fact[bool]
	SNMP         Fact[bool] // SNMP agent
	VirtualMedia Fact[bool]
	SSDP         Fact[bool]
	VNC          Fact[bool] // VNC server (DMTF RFB)
	KVMIP        Fact[bool] // the vendor's own virtual console protocol
	NTP          Fact[bool]
	Syslog       Fact[bool] // remote syslog

	SSHPort, HTTPPort, HTTPSPort, VNCPort Fact[int]

	// IPMIPrivLimit is the IPMI LAN channel privilege limit (Dell IPMILan.1.PrivLimit).
	IPMIPrivLimit Fact[string]
	// IPMICipherZero: cipher suite 0 (no authentication) accepted. No Dell iDRAC
	// resource reports it over Redfish; it is here for readers that can.
	IPMICipherZero Fact[bool]
	// SNMPLegacy: SNMP v1 or v2c accepted (community strings in clear).
	SNMPLegacy Fact[bool]
	// HTTPSRedirect: plain HTTP requests are redirected to HTTPS.
	HTTPSRedirect Fact[bool]
	// VNCTLS: whether the VNC server encrypts: off, optional (a TLS client gets TLS,
	// a plain client gets plain VNC: Dell's "Auto Negotiate") or required.
	VNCTLS Fact[Encryption]
	// NTPServers lists the configured NTP servers (", "-joined, at most a few).
	NTPServers Fact[string]
	// SyslogServers counts the configured remote syslog servers.
	SyslogServers Fact[int]
	// WebTLSPolicy is the vendor's TLS version setting (Dell WebServer.1.TLSProtocol);
	// shown as evidence only, the probe measures what is really offered.
	WebTLSPolicy Fact[string]
}

// Encryption is whether a service encrypts its connections.
type Encryption string

// Encryption modes.
const (
	EncryptionOff      Encryption = "off"
	EncryptionOptional Encryption = "optional" // encrypted and plain clients are both accepted
	EncryptionRequired Encryption = "required"
)

// Account is one BMC user account: name and role only (never a password or key).
type Account struct {
	UserName string
	Role     string // Redfish RoleId (Administrator, Operator, ReadOnly, None) or a custom role
	// Enabled is unknown when the BMC does not report the state; the checks then count
	// the account as enabled rather than let a factory account hide.
	Enabled Fact[bool]
	Locked  bool
	IPMI    Fact[bool] // may use IPMI over LAN
	SOL     Fact[bool] // may use serial over LAN
}

// AccountFacts are the BMC's accounts and its password and lockout policy
// (AccountService, or vendor attributes).
type AccountFacts struct {
	Read Section // AccountService
	List Section // the accounts themselves
	// ListSource names where the accounts came from.
	ListSource string
	// Partial: the list was cut (more members than the reader walks, or a page not
	// followed), so accounts may be missing from it.
	Partial           bool
	MinPasswordLength Fact[int]
	LockoutThreshold  Fact[int]           // failed logins before a lockout; 0 = none
	LockoutDuration   Fact[time.Duration] // 0 = until an admin unlocks it

	accounts []Account
}

// Accounts returns a copy of the account list.
func (a AccountFacts) Accounts() []Account { return slices.Clone(a.accounts) }

// WithAccounts returns a copy with the account list replaced (copied).
func (a AccountFacts) WithAccounts(list []Account) AccountFacts {
	a.accounts = slices.Clone(list)
	return a
}

// ClockFacts compare the BMC clock with the app clock.
type ClockFacts struct {
	Read    Section   // the Manager resource
	BMCTime time.Time // Manager.DateTime
	// Before and After are the app clock just before and after the read.
	Before, After time.Time
}

// FirmwareFacts are the BMC and BIOS versions.
type FirmwareFacts struct {
	Read        Section // the Manager resource
	BMCVersion  string
	BMCReleased Fact[time.Time] // release date of the running BMC image, when reported
	BIOSVersion Fact[string]
}

// LicenseEntry is one installed licence: its name, type and expiry (never its ID).
type LicenseEntry struct {
	Description string
	Type        string    // Production, Trial, Evaluation, Perpetual… as reported
	Expires     time.Time // zero: no expiry reported
	Tier        LicenseTier
}

// LicenseFacts are the installed licences (DMTF LicenseService).
type LicenseFacts struct {
	Read Section

	licenses []LicenseEntry
}

// Licenses returns a copy of the licence list.
func (l LicenseFacts) Licenses() []LicenseEntry { return slices.Clone(l.licenses) }

// WithLicenses returns a copy with the licence list replaced (copied).
func (l LicenseFacts) WithLicenses(list []LicenseEntry) LicenseFacts {
	l.licenses = slices.Clone(list)
	return l
}

// NetworkFacts are the BMC's own network settings.
type NetworkFacts struct {
	// IPFilter: only an allowed address range may connect (Dell IPBlocking range).
	IPFilter      Fact[bool]
	IPFilterRange Fact[string] // CIDR of the allowed range
	// LoginBlocking: an address is blocked after repeated failed logins.
	LoginBlocking Fact[bool]
	DHCP          Fact[bool] // the BMC takes its IPv4 address from DHCP
	IPv6          Fact[bool]
}

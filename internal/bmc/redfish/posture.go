package redfish

import (
	"context"
	"errors"
	"strings"
	"time"

	"oob-manager/internal/bmc"
)

// Caps on the members a posture read walks, so a BMC cannot make one run unbounded.
const (
	maxPostureAccounts = 16 // Dell iDRACs have 16 account slots
	maxPostureLicenses = 16
)

// PostureOptions tune Posture for an OEM driver.
type PostureOptions struct {
	// SkipAccountList leaves the account walk out (one GET per account): the OEM driver
	// lists the accounts from a single vendor document instead.
	SkipAccountList bool
	// Refused: a read of this run was already refused (401/403) before Posture was
	// called, by the OEM driver's own document. In Basic auth mode nothing more is read
	// (every section is skipped); in session mode it changes nothing.
	Refused bool
}

// skippedAfterRefusal is why a section was not read after a refusal in Basic auth mode.
const skippedAfterRefusal = "an earlier request of this run was refused, and in Basic auth mode each refusal may count as a failed login"

// errSkippedAfterRefusal marks a read the run did not make (postureRun.read).
var errSkippedAfterRefusal = errors.New("redfish: posture read skipped after a refusal")

// BasicAuth reports whether the driver sends the credentials on every request (Basic
// auth mode) instead of holding a session.
func (d *Driver) BasicAuth() bool { return d.cfg.Auth == AuthBasic }

// Warm makes one normal GET (the Manager) so that a session the BMC expired is renewed
// before a series of ReadOptional calls, which never log in again. In Basic auth mode
// there is no session and nothing is sent. The error is the Manager read's.
func (d *Driver) Warm(ctx context.Context) error {
	if d.BasicAuth() {
		return nil
	}
	res, err := d.Resources(ctx)
	if err != nil || res.Manager == "" {
		return err
	}
	var doc struct{}
	return d.GetJSON(ctx, res.Manager, &doc)
}

// Posture reads the BMC's security settings for the security checks (docs/tech_doc.md
// §31) with GETs only: ManagerNetworkProtocol, AccountService and its accounts, the
// Manager's clock and firmware, the BIOS version and the DMTF licences. A resource the
// read-only account may not read is a ReadForbidden section; the error is only for a
// BMC that answers nothing at all. In Basic auth mode the first refusal ends the
// optional reads of the run (the sections after it are ReadSkipped), because a BMC may
// count every refused request as a failed login.
func (d *Driver) Posture(ctx context.Context) (bmc.RedfishPosture, error) {
	return d.PostureWith(ctx, PostureOptions{})
}

// PostureWith is Posture with options.
func (d *Driver) PostureWith(ctx context.Context, o PostureOptions) (bmc.RedfishPosture, error) {
	res, err := d.Resources(ctx)
	if err != nil {
		return bmc.RedfishPosture{}, err
	}
	r := &postureRun{d: d, stop: d.BasicAuth(), refused: d.BasicAuth() && o.Refused}
	var p bmc.RedfishPosture
	mgr, err := r.postureManager(ctx, res.Manager, &p)
	if err != nil {
		return bmc.RedfishPosture{}, err
	}
	npURI := mgr.NetworkProtocol.ID
	if npURI == "" && res.Manager != "" {
		npURI = res.Manager + "/NetworkProtocol" // DSP0268 well-known location
	}
	var np networkProtocolDoc
	p.Protocols, np = r.postureProtocols(ctx, npURI)
	p.Network = networkFrom(np)
	p.Accounts = r.postureAccounts(ctx, res.AccountService, o)
	p.Firmware.BIOSVersion = r.biosVersion(ctx, res.System)
	p.Firmware.BMCReleased = r.releaseDate(ctx, mgr.Links.ActiveSoftwareImage.ID)
	p.Licenses = r.postureLicenses(ctx, res.LicenseService)
	return p, nil
}

// postureRun is one Posture read. In Basic auth mode (stop) the first 401/403 sets
// refused, and every later read of the run is skipped instead of sent.
type postureRun struct {
	d       *Driver
	stop    bool
	refused bool
}

// read is ReadOptional for the run: skipped once a refusal has ended the run.
func (r *postureRun) read(ctx context.Context, uri string, v any) error {
	if r.refused {
		return errSkippedAfterRefusal
	}
	err := r.d.ReadOptional(ctx, uri, v)
	if r.stop && errors.Is(err, bmc.ErrAuth) {
		r.refused = true
	}
	return err
}

// get is GetJSON for the run (the Manager read, which may log in again): skipped too
// once a refusal has ended the run.
func (r *postureRun) get(ctx context.Context, uri string, v any) error {
	if r.refused {
		return errSkippedAfterRefusal
	}
	err := r.d.GetJSON(ctx, uri, v)
	if r.stop && errors.Is(err, bmc.ErrAuth) {
		r.refused = true
	}
	return err
}

// sectionOf is bmc.SectionOf, plus the run's own skip.
func sectionOf(err error) bmc.Section {
	if errors.Is(err, errSkippedAfterRefusal) {
		return bmc.Skipped(skippedAfterRefusal)
	}
	return bmc.SectionOf(err)
}

// managerPostureDoc is the part of the Manager the security checks read.
type managerPostureDoc struct {
	FirmwareVersion string   `json:"FirmwareVersion"`
	DateTime        string   `json:"DateTime"`
	NetworkProtocol odataRef `json:"NetworkProtocol"`
	Links           struct {
		ActiveSoftwareImage odataRef `json:"ActiveSoftwareImage"`
	} `json:"Links"`
}

// postureManager reads the Manager first and with the normal GET (a login, and a
// re-login on a stale session): if even that cannot reach the BMC, the run has failed.
// A refused Manager is a forbidden section, not a failed run.
func (r *postureRun) postureManager(ctx context.Context, uri string, p *bmc.RedfishPosture) (managerPostureDoc, error) {
	var doc managerPostureDoc
	if uri == "" {
		p.Clock.Read, p.Firmware.Read = bmc.Section{State: bmc.ReadAbsent}, bmc.Section{State: bmc.ReadAbsent}
		return doc, nil
	}
	before := r.d.opts.now()
	err := r.get(ctx, uri, &doc)
	after := r.d.opts.now()
	sec := sectionOf(err)
	if sec.State == bmc.ReadFailed && !errors.Is(err, bmc.ErrDecode) {
		return doc, err
	}
	p.Firmware.Read, p.Firmware.BMCVersion = sec, clean(doc.FirmwareVersion)
	p.Clock = bmc.ClockFacts{Read: sec, Before: before, After: after}
	if sec.OK() {
		t, perr := time.Parse(time.RFC3339, strings.TrimSpace(doc.DateTime))
		if perr != nil {
			p.Clock.Read = bmc.Section{State: bmc.ReadFailed, Class: bmc.ClassProtocol}
		}
		p.Clock.BMCTime = t.UTC()
	}
	return doc, nil
}

func (r *postureRun) biosVersion(ctx context.Context, system string) bmc.Fact[string] {
	var doc struct {
		BiosVersion string `json:"BiosVersion"`
	}
	if system == "" || r.read(ctx, system, &doc) != nil || clean(doc.BiosVersion) == "" {
		return bmc.Fact[string]{}
	}
	return bmc.FactOf(clean(doc.BiosVersion), "ComputerSystem.BiosVersion")
}

// releaseDate is the ReleaseDate of the running BMC image. Dell writes "00:00:00Z" when
// it has none; anything that is not a full RFC 3339 time after 2000 is unknown.
func (r *postureRun) releaseDate(ctx context.Context, image string) bmc.Fact[time.Time] {
	var doc struct {
		ReleaseDate string `json:"ReleaseDate"`
	}
	if image == "" || r.read(ctx, image, &doc) != nil {
		return bmc.Fact[time.Time]{}
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(doc.ReleaseDate))
	if err != nil || t.Year() < 2000 {
		return bmc.Fact[time.Time]{}
	}
	return bmc.FactOf(t.UTC(), "SoftwareInventory.ReleaseDate")
}

type licenseMemberDoc struct {
	Description    string  `json:"Description"`
	LicenseType    string  `json:"LicenseType"`
	ExpirationDate *string `json:"ExpirationDate"`
}

// postureLicenses reads the DMTF LicenseService members: description, type and expiry
// only (never the licence or entitlement IDs).
func (r *postureRun) postureLicenses(ctx context.Context, service string) bmc.LicenseFacts {
	if service == "" {
		return bmc.LicenseFacts{Read: bmc.Section{State: bmc.ReadAbsent}}
	}
	var svc struct {
		Licenses odataRef `json:"Licenses"`
	}
	if err := r.read(ctx, service, &svc); err != nil {
		return bmc.LicenseFacts{Read: sectionOf(err)}
	}
	uri := svc.Licenses.ID
	if uri == "" {
		uri = service + "/Licenses"
	}
	var col collectionDoc
	if err := r.read(ctx, uri, &col); err != nil {
		return bmc.LicenseFacts{Read: sectionOf(err)}
	}
	var out []bmc.LicenseEntry
	for _, m := range firstN(col.uris(), maxPostureLicenses) {
		var doc licenseMemberDoc
		err := r.read(ctx, m, &doc)
		if errors.Is(err, bmc.ErrNotFound) {
			continue
		}
		if err != nil {
			return bmc.LicenseFacts{Read: sectionOf(err)}
		}
		out = append(out, licenseEntry(doc))
	}
	return bmc.LicenseFacts{Read: bmc.SectionOf(nil)}.WithLicenses(out)
}

func licenseEntry(doc licenseMemberDoc) bmc.LicenseEntry {
	desc := clean(doc.Description)
	e := bmc.LicenseEntry{Description: desc, Type: clean(doc.LicenseType), Tier: bmc.ParseLicenseTier(desc)}
	if doc.ExpirationDate != nil {
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(*doc.ExpirationDate)); err == nil {
			e.Expires = t.UTC()
		}
	}
	return e
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

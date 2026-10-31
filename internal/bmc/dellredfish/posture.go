package dellredfish

import (
	"context"
	"encoding/json"
	"errors"
	"path"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfish"
)

// Posture is the generic Redfish posture with the iDRAC Manager attributes laid over
// it (docs/tech_doc.md §31). The attribute document is read with one GET: from
// <manager>/Attributes (iDRAC8, and iDRAC9 until it was deprecated), else from
// <manager>/Oem/Dell/DellAttributes/<manager id> (iDRAC9 7.x). Only an allowlist of
// non-secret keys is kept (attrKeep); the document also carries secrets (the IPMI
// encryption key, SNMP community strings, password hashes on some firmware), which are
// dropped as soon as it is decoded. When it lists the users, the per-account GETs
// (sixteen slots on an iDRAC) are skipped.
//
// The attribute document is an optional read (ReadOptional never logs in again), so the
// session is renewed first (Warm): an expired session must read as "forbidden" nowhere.
// In Basic auth mode a refused attribute document ends the run: a BMC may count every
// refused request as a failed login, so the generic posture then reads nothing.
//
// Whether the read-only account may read the attribute document and AccountService on
// iDRAC8 2.86 and iDRAC9 7.00 is not verified on hardware: a refusal makes those
// sections ReadForbidden and the checks report "can't read".
func (d *Driver) Posture(ctx context.Context) (bmc.RedfishPosture, error) {
	res, err := d.base.Resources(ctx)
	if err != nil {
		return bmc.RedfishPosture{}, err
	}
	// A refused Manager is a forbidden section for the generic reader, not a failed run;
	// Warm only renews the session, so its refusal is not the run's error either.
	if werr := d.base.Warm(ctx); werr != nil && !errors.Is(werr, bmc.ErrAuth) {
		return bmc.RedfishPosture{}, werr
	}
	attrs, sec := d.readAttributes(ctx, res.Manager)
	users := attrs.users()
	opts := redfish.PostureOptions{SkipAccountList: len(users) > 0, Refused: sec.State == bmc.ReadForbidden}
	p, err := d.base.PostureWith(ctx, opts)
	if err != nil {
		return bmc.RedfishPosture{}, err
	}
	p.Attributes = sec
	if !sec.OK() {
		return p, nil
	}
	return attrs.apply(p, users), nil
}

type attrsDocument struct {
	Attributes map[string]json.RawMessage `json:"Attributes"`
}

// readAttributes tries the attribute locations in order; a 404 moves on, anything else
// ends the search with that outcome.
func (d *Driver) readAttributes(ctx context.Context, manager string) (dellAttrs, bmc.Section) {
	if manager == "" {
		return nil, bmc.Section{State: bmc.ReadAbsent}
	}
	for _, uri := range []string{manager + "/Attributes", manager + "/Oem/Dell/DellAttributes/" + path.Base(manager)} {
		var doc attrsDocument
		err := d.base.ReadOptional(ctx, uri, &doc)
		if errors.Is(err, bmc.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, bmc.SectionOf(err)
		}
		return keepAttrs(doc.Attributes), bmc.SectionOf(nil)
	}
	return nil, bmc.Section{State: bmc.ReadAbsent}
}

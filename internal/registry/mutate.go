package registry

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/config"
	"oob-manager/internal/netpolicy"
	"oob-manager/internal/secrets"
	"oob-manager/internal/secrets/credstore"
	"oob-manager/internal/store"
)

// editFn returns the next row and the audited changes (none: nothing is written).
type editFn func(ctx context.Context, tx *store.Tx, cur store.ServerRow) (store.ServerRow, []Change, error)

// editable refuses changes to file servers and to a locked section.
func (s *Service) editable(id string) error {
	e := s.Current()
	if e.Locked {
		return ErrLocked
	}
	if x, ok := e.Entry(id); ok && x.Source == SourceFile {
		return ErrLocked
	}
	return nil
}

// edit runs fn on server id at revision rev in one transaction with the audit row,
// validates the result like config.yaml (plus the address policy; an enabled server
// must stay complete) and publishes the new registry.
func (s *Service) edit(ctx context.Context, a admin.Actor, action, id string, rev int64, fn editFn) ([]Change, error) {
	if err := s.editable(id); err != nil {
		s.deny(ctx, a, action, id, err)
		return nil, err
	}
	var changes []Change
	var published Effective
	err := s.cfg.DB.WithTx(ctx, func(tx *store.Tx) error {
		cur, err := tx.Servers().Get(ctx, id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return ErrNotFound
		case err != nil:
			return err
		case cur.Rev != rev:
			return ErrConflict
		}
		next, ch, err := fn(ctx, tx, cur)
		if err != nil || len(ch) == 0 {
			return err
		}
		next.UpdatedAt, next.UpdatedBy = s.cfg.Now(), a.Username
		if err = s.check(ctx, tx, next); err != nil {
			return err
		}
		if err = tx.Servers().Update(ctx, next, rev); err != nil {
			return err
		}
		if _, err = s.cfg.Audit.RecordTx(ctx, tx, entry(a, action, id, params(id, ch, rev+1, nil))); err != nil {
			return err
		}
		changes = ch
		published, err = s.load(ctx, tx.Servers(), tx.Credentials())
		return err
	})
	if errors.Is(err, store.ErrConflict) {
		err = ErrConflict
	}
	if err != nil {
		s.deny(ctx, a, action, id, err)
		return nil, err
	}
	if changes != nil {
		s.publish(published)
	}
	return changes, nil
}

// check validates a row before it is written: the config.yaml rules as if every
// credential were stored, and the address policy; an enabled row must also have the
// credentials its features need.
func (s *Service) check(ctx context.Context, tx *store.Tx, r store.ServerRow) error {
	creds, err := tx.Credentials().List(ctx, r.ID)
	if err != nil {
		return err
	}
	stored := map[credstore.Slot]bool{}
	for _, c := range creds {
		stored[credstore.Slot(c.Slot)] = true
	}
	srv := serverOf(r, stored)
	var p []string
	if _, aerr := netpolicy.CheckBMCAddr(r.Address, s.policy); aerr != nil {
		p = append(p, "bmc.address: "+reasonOf(aerr))
	}
	p = append(p, config.ValidateServer(withAllRefs(srv))...)
	if lo := max(config.PollFloor, s.cfg.File.Poll.MinInterval); r.PollInterval != 0 &&
		(r.PollInterval < lo || r.PollInterval > config.MaxPollInterval) {
		p = append(p, fmt.Sprintf("poll.interval %v must be between %v and %v", r.PollInterval, lo, config.MaxPollInterval))
	}
	if len(p) == 0 && r.Enabled {
		p = config.ValidateServer(srv)
	}
	if len(p) > 0 {
		return invalid(p)
	}
	return nil
}

// Draft is a new server: identity, connection and the confirmed HTTPS pin.
type Draft struct {
	ID, Name string
	Tags     []string
	Kind     config.BMCKind
	Address  string
	Port     int
	TLSPin   string
	// PinVia is how the pin was confirmed: "tofu" (fetched, proof checked) or "manual".
	PinVia string
}

// Create adds a disabled server with no credentials and no features (safe defaults).
func (s *Service) Create(ctx context.Context, a admin.Actor, d Draft) (Entry, error) {
	if s.Current().Locked {
		s.deny(ctx, a, ActionCreate, d.ID, ErrLocked)
		return Entry{}, ErrLocked
	}
	if slices.ContainsFunc(s.cfg.File.Servers, func(f config.Server) bool { return f.ID == d.ID }) {
		s.deny(ctx, a, ActionCreate, d.ID, ErrExists)
		return Entry{}, ErrExists
	}
	srv := config.Normalise(config.Server{ID: d.ID, Name: d.Name, Tags: d.Tags,
		BMC: config.BMCConfig{Address: d.Address, Kind: d.Kind, Port: d.Port}, TLSPinSHA256: d.TLSPin})
	now := s.cfg.Now()
	row := rowOf(srv)
	row.CreatedAt, row.CreatedBy, row.UpdatedAt, row.UpdatedBy = now, a.Username, now, a.Username
	var published Effective
	err := s.cfg.DB.WithTx(ctx, func(tx *store.Tx) error {
		if err := s.check(ctx, tx, row); err != nil {
			return err
		}
		if err := tx.Servers().Insert(ctx, row); err != nil {
			return err
		}
		ch := diffRows(store.ServerRow{}, row)
		e := entry(a, ActionCreate, d.ID, params(d.ID, ch, 1, map[string]any{"pin_via": d.PinVia}))
		if _, err := s.cfg.Audit.RecordTx(ctx, tx, e); err != nil {
			return err
		}
		var lerr error
		published, lerr = s.load(ctx, tx.Servers(), tx.Credentials())
		return lerr
	})
	if errors.Is(err, store.ErrConflict) {
		err = ErrExists
	}
	if err != nil {
		s.deny(ctx, a, ActionCreate, d.ID, err)
		return Entry{}, err
	}
	s.publish(published)
	x, _ := published.DBEntry(d.ID)
	return x, nil
}

// UpdateIdentity changes the display name and tags.
func (s *Service) UpdateIdentity(ctx context.Context, a admin.Actor, id string, rev int64, name string, tags []string) ([]Change, error) {
	return s.edit(ctx, a, ActionUpdate, id, rev, func(_ context.Context, _ *store.Tx, cur store.ServerRow) (store.ServerRow, []Change, error) {
		next := cur.Clone()
		next.Name, next.Tags = name, slices.Clone(tags)
		return next, diffRows(cur, next), nil
	})
}

// Connection is where a server's BMC is: kind, address, port and the confirmed HTTPS
// pin of that address (a new address is a new BMC: its fingerprint is confirmed again).
type Connection struct {
	Kind    config.BMCKind
	Address string
	Port    int
	TLSPin  string
	PinVia  string // "tofu" or "manual"
}

// UpdateConnection moves a server to another kind, address or port. Stored credentials
// can never follow a server to a new BMC: they are deleted, the VNC pin and SSH host key
// are cleared and the server is disabled until they are confirmed and entered again.
// Refused while a fan lease is active.
func (s *Service) UpdateConnection(ctx context.Context, a admin.Actor, id string, rev int64, c Connection) ([]Change, error) {
	if x, ok := s.Current().DBEntry(id); ok && (x.Server.BMC.Kind != c.Kind || x.Server.BMC.Address != c.Address ||
		x.Server.BMC.Port != c.Port) {
		if err := s.noLease(ctx, id); err != nil { // before the transaction: the store has one connection
			s.deny(ctx, a, ActionUpdate, id, err)
			return nil, err
		}
	}
	return s.edit(ctx, a, ActionUpdate, id, rev, func(ctx context.Context, tx *store.Tx, cur store.ServerRow) (store.ServerRow, []Change, error) {
		if cur.Kind == string(c.Kind) && cur.Address == c.Address && cur.Port == c.Port {
			return cur, nil, nil
		}
		next := cur.Clone()
		next.Kind, next.Address, next.Port, next.TLSPin = string(c.Kind), c.Address, c.Port, c.TLSPin
		next.VNCPin, next.SSHHostKey, next.Enabled = "", "", false
		ch := diffRows(cur, next)
		for i := range ch {
			if ch[i].Field == "tls_pin_sha256" {
				ch[i].After += " (" + c.PinVia + ")"
			}
		}
		creds, err := tx.Credentials().List(ctx, id)
		if err != nil {
			return cur, nil, err
		}
		for _, cr := range creds {
			ch = append(ch, credChange(cr.Slot, cr.Version, 0))
		}
		if _, err = tx.Credentials().DeleteAll(ctx, id); err != nil {
			return cur, nil, err
		}
		return next, ch, nil
	})
}

func (s *Service) noLease(ctx context.Context, id string) error {
	active, err := s.cfg.LeaseActive(ctx, id)
	switch {
	case err != nil:
		return err
	case active:
		return ErrLeaseActive
	}
	return nil
}

// Features are the per-server features (fans, consoles, power context, poll interval).
type Features struct {
	FanMode     config.FanMode
	FanSafeMin  int
	FanMaxLease time.Duration
	Serial      config.SerialKind
	Graphical   config.GraphicalKind
	VNCPort     int
	SSHPort     int
	SelfHost    bool
	Impact      []string
	// PollInterval overrides poll.interval for this server (0: the app's).
	PollInterval time.Duration
}

// UpdateFeatures changes fans, consoles, power context and the poll interval. A fan
// change is refused while a fan lease is active.
func (s *Service) UpdateFeatures(ctx context.Context, a admin.Actor, id string, rev int64, f Features) ([]Change, error) {
	if x, ok := s.Current().DBEntry(id); ok && fanChanged(x.Server.Fan, f) {
		if err := s.noLease(ctx, id); err != nil { // before the transaction: the store has one connection
			s.deny(ctx, a, ActionUpdate, id, err)
			return nil, err
		}
	}
	return s.edit(ctx, a, ActionUpdate, id, rev, func(_ context.Context, _ *store.Tx, cur store.ServerRow) (store.ServerRow, []Change, error) {
		next := cur.Clone()
		next.FanMode, next.FanSafeMinPct, next.FanMaxLease = string(f.FanMode), f.FanSafeMin, f.FanMaxLease
		next.ConsoleSerial, next.ConsoleGraphical = string(f.Serial), string(f.Graphical)
		next.VNCPort, next.SSHPort = f.VNCPort, f.SSHPort
		next.PowerSelfHost, next.PowerImpact = f.SelfHost, slices.Clone(f.Impact)
		next.PollInterval = f.PollInterval
		if next.FanMode == string(config.FanNone) {
			next.FanSafeMinPct, next.FanMaxLease = 0, 0
		}
		return next, diffRows(cur, next), nil
	})
}

// fanChanged reports whether f changes the fan settings of cur.
func fanChanged(cur config.FanConfig, f Features) bool {
	if f.FanMode == config.FanNone {
		return cur.Mode != config.FanNone
	}
	return f.FanMode != cur.Mode || f.FanSafeMin != cur.SafeMinPct || f.FanMaxLease != cur.MaxLease
}

// ErrUnknownPin is returned for a pin kind other than tls, vnc or ssh.
var ErrUnknownPin = errors.New("unknown fingerprint kind")

// SetPin stores a confirmed fingerprint: kind "tls" (HTTPS SPKI), "vnc" (VNC port SPKI,
// "" = same as HTTPS) or "ssh" (host key line). Credentials are kept (decision 2: they
// are not bound to the pin). via is "tofu" or "manual", recorded in the audit row.
func (s *Service) SetPin(ctx context.Context, a admin.Actor, id string, rev int64, kind, value, via string) ([]Change, error) {
	return s.edit(ctx, a, ActionPin, id, rev, func(_ context.Context, _ *store.Tx, cur store.ServerRow) (store.ServerRow, []Change, error) {
		next := cur.Clone()
		switch kind {
		case "tls":
			next.TLSPin = value
		case "vnc":
			next.VNCPin = value
		case "ssh":
			next.SSHHostKey = value
		default:
			return cur, nil, ErrUnknownPin
		}
		ch := diffRows(cur, next)
		for i := range ch {
			ch[i].After += " (" + via + ")"
		}
		return next, ch, nil
	})
}

// SetCredential replaces (never shows) the credential of slot. It is sealed for the
// server's current kind, address and port with a new version.
func (s *Service) SetCredential(ctx context.Context, a admin.Actor, id string, rev int64, slot credstore.Slot,
	username, password string) ([]Change, error) {
	return s.edit(ctx, a, ActionCredential, id, rev, func(ctx context.Context, tx *store.Tx, cur store.ServerRow) (store.ServerRow, []Change, error) {
		before := 0
		if creds, err := tx.Credentials().List(ctx, id); err == nil {
			for _, c := range creds {
				if c.Slot == string(slot) {
					before = c.Version
				}
			}
		}
		v, err := tx.Servers().NextCredVersion(ctx, id)
		if err != nil {
			return cur, nil, err
		}
		blob, err := s.cfg.Creds.Seal(binding(cur, slot, v), secrets.Credential{Username: username, Password: secrets.New(password)})
		if errors.Is(err, credstore.ErrEmpty) {
			return cur, nil, fmt.Errorf("%w: %s needs %s", ErrInvalid, slot.Label(), needs(slot))
		}
		if err != nil {
			return cur, nil, err
		}
		if err = tx.Credentials().Put(ctx, store.CredentialRow{ServerID: id, Slot: string(slot), Version: v,
			KeyID: credstore.KeyID, SecretEnc: blob, CreatedAt: s.cfg.Now(), CreatedBy: a.Username}); err != nil {
			return cur, nil, err
		}
		return cur.Clone(), []Change{credChange(string(slot), before, v)}, nil
	})
}

func needs(slot credstore.Slot) string {
	if slot.Login() {
		return "a username and a password"
	}
	return "a password"
}

// SetEnabled turns polling and features on or off. Enabling needs a complete server
// (every credential its features use, a pin, a valid address); disabling restores any
// fan lease first (the reconcile does it) and ends its consoles.
func (s *Service) SetEnabled(ctx context.Context, a admin.Actor, id string, rev int64, on bool) ([]Change, error) {
	action := ActionDisable
	if on {
		action = ActionEnable
	}
	return s.edit(ctx, a, action, id, rev, func(_ context.Context, _ *store.Tx, cur store.ServerRow) (store.ServerRow, []Change, error) {
		next := cur.Clone()
		next.Enabled = on
		return next, diffRows(cur, next), nil
	})
}

// Delete removes a database server with its credentials, the security checks' rows
// about it (accepted risks, notification state) and its firmware view rows. A shadowed row can be deleted too (it
// only cleans up the database).
func (s *Service) Delete(ctx context.Context, a admin.Actor, id string, rev int64) error {
	if s.Current().Locked {
		s.deny(ctx, a, ActionDelete, id, ErrLocked)
		return ErrLocked
	}
	var published Effective
	err := s.cfg.DB.WithTx(ctx, func(tx *store.Tx) error {
		cur, err := tx.Servers().Get(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err = tx.Servers().Delete(ctx, id, rev); err != nil {
			return err
		}
		// The security checks' accepted risks and notification state belong to the
		// server: they go with it, so a later server with the same ID starts clean. A
		// shadowed row is only a database copy of a live file-managed server, whose rows
		// stay.
		if x, ok := s.Current().DBEntry(id); ok && !x.Shadowed {
			if err = tx.Security().DeleteServer(ctx, id); err != nil {
				return err
			}
			if err = tx.Firmware().DeleteServer(ctx, id); err != nil {
				return err
			}
			if err = tx.FirmwareUpdates().DeleteServer(ctx, id); err != nil {
				return err
			}
		}
		ch := diffRows(cur, store.ServerRow{})
		if _, err = s.cfg.Audit.RecordTx(ctx, tx, entry(a, ActionDelete, id, params(id, ch[:min(len(ch), 4)], 0, nil))); err != nil {
			return err
		}
		published, err = s.load(ctx, tx.Servers(), tx.Credentials())
		return err
	})
	if errors.Is(err, store.ErrConflict) {
		err = ErrConflict
	}
	if err != nil {
		s.deny(ctx, a, ActionDelete, id, err)
		return err
	}
	s.publish(published)
	return nil
}

package registry

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"oob-manager/internal/admin"
	"oob-manager/internal/config"
	"oob-manager/internal/netpolicy"
	"oob-manager/internal/secrets"
	"oob-manager/internal/secrets/credstore"
	"oob-manager/internal/store"
)

// ImportResult describes one imported server.
type ImportResult struct {
	ID string
	// Dropped lists file-only settings the database cannot hold (the kind defaults
	// apply after the import).
	Dropped []string
}

// Import copies config.yaml servers into the database (CLI `settings import`, run from
// the trusted shell). Each server is stored enabled, with its credentials decrypted from
// the age file and re-sealed into the database; the copy stays shadowed until the
// server is removed from config.yaml. Everything is one transaction: any problem
// imports nothing.
func (s *Service) Import(ctx context.Context, a admin.Actor, ids []string, file secrets.Credentials) ([]ImportResult, error) {
	var out []ImportResult
	err := s.cfg.DB.WithTx(ctx, func(tx *store.Tx) error {
		for _, id := range ids {
			res, err := s.importOne(ctx, tx, a, id, file)
			if err != nil {
				return fmt.Errorf("server %s: %w", id, err)
			}
			out = append(out, res)
		}
		published, err := s.load(ctx, tx.Servers(), tx.Credentials())
		if err == nil {
			tx.AfterCommit(func() { s.publish(published) })
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) importOne(ctx context.Context, tx *store.Tx, a admin.Actor, id string, file secrets.Credentials) (ImportResult, error) {
	srv, ok := s.cfg.File.Server(id)
	if !ok {
		return ImportResult{}, errors.New("not in config.yaml")
	}
	if _, err := netpolicy.CheckBMCAddr(srv.BMC.Address, s.policy); err != nil {
		return ImportResult{}, fmt.Errorf("bmc.address: %s (add its network to settings.bmc_networks)", reasonOf(err))
	}
	now := s.cfg.Now()
	row := rowOf(srv)
	row.Enabled, row.CreatedAt, row.CreatedBy, row.UpdatedAt, row.UpdatedBy = true, now, a.Username, now, a.Username
	if err := tx.Servers().Insert(ctx, row); errors.Is(err, store.ErrConflict) {
		return ImportResult{}, ErrExists
	} else if err != nil {
		return ImportResult{}, err
	}
	ch := diffRows(store.ServerRow{}, row)
	refs := map[credstore.Slot]string{credstore.SlotReadOnly: srv.Credentials.ReadOnly,
		credstore.SlotOperator: srv.Credentials.Operator, credstore.SlotVNC: srv.Credentials.VNC}
	for _, slot := range credstore.Slots() {
		if refs[slot] == "" {
			continue
		}
		c, err := s.sealFrom(ctx, tx, a, row, slot, refs[slot], file)
		if err != nil {
			return ImportResult{}, err
		}
		ch = append(ch, c)
	}
	if err := s.check(ctx, tx, row); err != nil {
		return ImportResult{}, err
	}
	if _, err := s.cfg.Audit.RecordTx(ctx, tx, entry(a, ActionImport, id, params(id, ch, 1, nil))); err != nil {
		return ImportResult{}, err
	}
	return ImportResult{ID: id, Dropped: dropped(srv)}, nil
}

func (s *Service) sealFrom(ctx context.Context, tx *store.Tx, a admin.Actor, row store.ServerRow, slot credstore.Slot,
	ref string, file secrets.Credentials) (Change, error) {
	cred, err := file.Lookup(ref)
	if err != nil {
		return Change{}, fmt.Errorf("credentials.%s %q: %w", slot, ref, err)
	}
	v, err := tx.Servers().NextCredVersion(ctx, row.ID)
	if err != nil {
		return Change{}, err
	}
	blob, err := s.cfg.Creds.Seal(binding(row, slot, v), cred)
	if err != nil {
		return Change{}, fmt.Errorf("credentials.%s %q: %w", slot, ref, err)
	}
	err = tx.Credentials().Put(ctx, store.CredentialRow{ServerID: row.ID, Slot: string(slot), Version: v,
		KeyID: credstore.KeyID, SecretEnc: blob, CreatedAt: s.cfg.Now(), CreatedBy: a.Username})
	return credChange(string(slot), 0, v), err
}

// dropped lists file-only settings of srv that differ from what a database server gets.
func dropped(srv config.Server) []string {
	def := config.Normalise(config.Server{BMC: config.BMCConfig{Kind: srv.BMC.Kind}})
	var out []string
	if srv.BMC.Auth != def.BMC.Auth {
		out = append(out, "bmc.auth")
	}
	if srv.BMC.Timeouts != def.BMC.Timeouts {
		out = append(out, "bmc.timeouts")
	}
	if !srv.Console.VNC.TLSEnabled() {
		out = append(out, "console.vnc.tls")
	}
	if !slices.Equal(srv.Console.VNC.Quirks, def.Console.VNC.Quirks) {
		out = append(out, "console.vnc.quirks")
	}
	if !slices.Equal(srv.Console.SSH.Quirks, def.Console.SSH.Quirks) {
		out = append(out, "console.ssh.quirks")
	}
	return out
}

// Export returns every running server as config.yaml would hold it, without secrets:
// file servers keep their credential refs; a database server's refs name its stored
// slots as "<id>-<slot>" (entries to create in the age file to move it to the file).
func Export(e Effective) []config.Server {
	var out []config.Server
	for _, x := range e.Active() {
		s := x.Server
		if x.Source == SourceDB {
			s.Credentials = exportRefs(s.ID, s.Credentials)
		}
		out = append(out, s)
	}
	return out
}

func exportRefs(id string, c config.CredentialRef) config.CredentialRef {
	ref := func(v string) string {
		if v == "" {
			return ""
		}
		return id + "-" + v
	}
	return config.CredentialRef{ReadOnly: ref(c.ReadOnly), Operator: ref(c.Operator), VNC: ref(c.VNC)}
}

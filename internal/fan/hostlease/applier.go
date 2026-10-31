package hostlease

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"oob-manager/internal/fan"
	"oob-manager/internal/store"
)

// DefaultStaleAfter is when an ack counts as stale: the host script runs every minute, so
// an ack older than three minutes means it stopped (or stopped reading the lease directory).
const DefaultStaleAfter = 3 * time.Minute

// leaseFileMode: readable by the host (root) and the app's group, never world.
const leaseFileMode = 0o640

// Config is one server's lease file location.
type Config struct {
	Dir        string // absolute lease directory (config storage.lease_dir)
	ServerID   string
	Now        func() time.Time
	StaleAfter time.Duration
}

// Applier writes and removes one server's lease file and reads its ack. Every file
// operation goes through an os.Root on Dir, so no name can escape the directory.
type Applier struct {
	cfg Config
}

var (
	_ fan.Applier = (*Applier)(nil)
	_ fan.Sweeper = (*Applier)(nil)
)

// New validates cfg. The directory is opened per operation, so it may appear later
// (a missing directory makes Apply fail, which the UI reports).
func New(cfg Config) (*Applier, error) {
	if !filepath.IsAbs(cfg.Dir) || !serverPattern.MatchString(cfg.ServerID) {
		return nil, fmt.Errorf("hostlease: need an absolute directory and a valid server id")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.StaleAfter <= 0 {
		cfg.StaleAfter = DefaultStaleAfter
	}
	return &Applier{cfg: cfg}, nil
}

func (a *Applier) leaseName() string { return a.cfg.ServerID + ".lease" }
func (a *Applier) ackName() string   { return a.cfg.ServerID + ".ack" }

// Prepare accepts the floor as is: the host clamps it to its own safe minimum and never
// goes below its computed curve. There is no BMC value to restore.
func (a *Applier) Prepare(_ context.Context, pct, _ int) (fan.Plan, error) {
	return fan.Plan{Pct: pct}, nil
}

// Apply writes the lease file atomically (temp file, fsync, rename, fsync directory).
// The lease is pending until the host acknowledges it.
func (a *Applier) Apply(_ context.Context, l store.FanLease) (bool, error) {
	body, err := encodeLease(l)
	if err != nil {
		return false, err
	}
	root, err := os.OpenRoot(a.cfg.Dir)
	if err != nil {
		return false, fmt.Errorf("hostlease: lease directory: %w", err)
	}
	defer root.Close()
	return false, writeAtomic(root, a.leaseName(), body)
}

func writeAtomic(root *os.Root, name string, body []byte) error {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := "." + name + "." + hex.EncodeToString(rnd[:]) + ".tmp"
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, leaseFileMode)
	if err != nil {
		return fmt.Errorf("hostlease: create: %w", err)
	}
	err = errors.Join(f.Chmod(leaseFileMode), writeAll(f, body), f.Sync(), f.Close())
	if err == nil {
		err = root.Rename(tmp, name)
	}
	if err != nil {
		_ = root.Remove(tmp)
		return fmt.Errorf("hostlease: write: %w", err)
	}
	return syncDir(root)
}

func writeAll(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}

func syncDir(root *os.Root) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// Release removes the lease file. The host then returns to its curve on its next run
// (and would anyway at expires_at).
func (a *Applier) Release(context.Context, store.FanLease) error {
	return a.remove()
}

// Sweep removes a lease file left without an active lease (crash between steps).
func (a *Applier) Sweep(context.Context) error { return a.remove() }

func (a *Applier) remove() error {
	root, err := os.OpenRoot(a.cfg.Dir)
	if err != nil {
		return fmt.Errorf("hostlease: lease directory: %w", err)
	}
	defer root.Close()
	if err := root.Remove(a.leaseName()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("hostlease: remove: %w", err)
	}
	return syncDir(root)
}

package firstrun

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// file is one file of a generated set.
type file struct {
	name string
	data []byte
	mode os.FileMode
}

// writeSet creates parent/name holding files, atomically: everything is written and
// synced in a temporary sibling directory, which is then renamed into place. It fails
// if parent/name already exists. dirMode applies to the final directory.
func writeSet(parent, name string, dirMode os.FileMode, files []file) error {
	tmp, err := os.MkdirTemp(parent, "."+name+"-tmp-*")
	if err != nil {
		return fmt.Errorf("firstrun: %w", err)
	}
	if err := fillSet(tmp, files); err != nil {
		return errors.Join(err, os.RemoveAll(tmp))
	}
	if err := os.Chmod(tmp, dirMode); err != nil {
		return errors.Join(fmt.Errorf("firstrun: %w", err), os.RemoveAll(tmp))
	}
	final := filepath.Join(parent, name)
	if _, err := os.Lstat(final); !errors.Is(err, fs.ErrNotExist) {
		return errors.Join(fmt.Errorf("firstrun: %s already exists", final), os.RemoveAll(tmp))
	}
	if err := os.Rename(tmp, final); err != nil {
		return errors.Join(fmt.Errorf("firstrun: %w", err), os.RemoveAll(tmp))
	}
	return syncDir(parent)
}

func fillSet(dir string, files []file) error {
	for _, f := range files {
		if err := writeFile(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
			return err
		}
	}
	return syncDir(dir)
}

// writeFile creates path (never an existing file), writes data, syncs it and sets mode
// (OpenFile's mode is filtered by the umask).
func writeFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: path built here
	if err != nil {
		return fmt.Errorf("firstrun: %w", err)
	}
	_, werr := f.Write(data)
	return errors.Join(werr, f.Sync(), f.Chmod(mode), f.Close())
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: a directory this package created or was given
	if err != nil {
		return fmt.Errorf("firstrun: %w", err)
	}
	return errors.Join(d.Sync(), d.Close())
}

// cleanTemp removes temporary set directories a crash left behind in parent. They were
// never renamed into place, so nothing ever used them.
func cleanTemp(parent, name string) error {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return fmt.Errorf("firstrun: %w", err)
	}
	var errs []error
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "."+name+"-tmp-") {
			errs = append(errs, os.RemoveAll(filepath.Join(parent, e.Name())))
		}
	}
	return errors.Join(errs...)
}

// setState reports which of paths exist: all, none, or the first missing one when only
// some do (a partial set, which callers refuse).
func setState(paths ...string) (all, none bool, missing string, err error) {
	present := 0
	for _, p := range paths {
		_, serr := os.Stat(p)
		switch {
		case serr == nil:
			present++
		case errors.Is(serr, fs.ErrNotExist):
			if missing == "" {
				missing = p
			}
		default:
			return false, false, "", fmt.Errorf("firstrun: %w", serr)
		}
	}
	return present == len(paths), present == 0, missing, nil
}

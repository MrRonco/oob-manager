package firstrun

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// CheckWritable reports whether dir is an existing directory this process can create
// files in. It runs before keys, certificates or migrations, so a wrong owner fails with
// the fix instead of halfway through an upgrade.
func CheckWritable(dir string) error {
	fi, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("data directory %s does not exist: mount a volume there", dir)
	case err != nil:
		return fmt.Errorf("data directory %s: %w", dir, err)
	case !fi.IsDir():
		return fmt.Errorf("data directory %s is not a directory", dir)
	}
	f, err := os.CreateTemp(dir, ".write-probe-*")
	if err != nil {
		return fmt.Errorf("data directory %s is not writable by uid %d gid %d: chown -R %d:%d the host "+
			"directory, or run the container with --user matching its owner (%w)",
			dir, os.Getuid(), os.Getgid(), os.Getuid(), os.Getgid(), err)
	}
	name := f.Name()
	return errors.Join(f.Close(), os.Remove(name))
}

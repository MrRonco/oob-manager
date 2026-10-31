package main

import (
	"flag"
	"fmt"
	"io"
)

// parseInterleaved parses fs over args, allowing flags before and after positional
// arguments (`token revoke <id> -config x` as well as `token revoke -config x <id>`),
// and returns the positional arguments in order.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// newFlagSet returns a FlagSet with the shared -config flag.
func newFlagSet(name string, stderr io.Writer) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs, addConfigFlag(fs)
}

// wantPositional checks the positional argument count.
func wantPositional(name string, pos []string, n int) error {
	if len(pos) != n {
		return fmt.Errorf("%s: expected %d argument(s), got %d", name, n, len(pos))
	}
	return nil
}

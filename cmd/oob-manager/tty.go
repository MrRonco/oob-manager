package main

import (
	"errors"
	"os"
)

var errNotTerminal = errors.New("stdin is not a terminal")

// stdinNoEcho turns off echo on the terminal behind stdin and returns a restore func.
func stdinNoEcho() (func(), error) {
	return noEchoFD(int(os.Stdin.Fd())) //nolint:gosec // file descriptors fit in int
}

// stdoutIsTerminal reports whether stdout is a terminal (secrets are only shown there).
func stdoutIsTerminal() bool {
	return isTerminalFD(int(os.Stdout.Fd())) //nolint:gosec // file descriptors fit in int
}

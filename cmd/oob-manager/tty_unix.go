//go:build linux || darwin

package main

import "golang.org/x/sys/unix"

// noEchoFD clears ECHO on fd (ECHONL kept so Enter still moves the cursor) and
// returns the function restoring the previous terminal state.
func noEchoFD(fd int) (func(), error) {
	old, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return nil, errNotTerminal
	}
	quiet := *old
	quiet.Lflag &^= unix.ECHO
	quiet.Lflag |= unix.ICANON | unix.ISIG | unix.ECHONL
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, &quiet); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, ioctlSetTermios, old) }, nil
}

// isTerminalFD reports whether fd is a terminal.
func isTerminalFD(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	return err == nil
}

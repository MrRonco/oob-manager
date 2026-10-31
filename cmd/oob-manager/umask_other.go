//go:build !linux && !darwin

package main

// restrictUmask is a no-op where there is no umask; it returns the "previous" value 0.
func restrictUmask() int { return 0 }

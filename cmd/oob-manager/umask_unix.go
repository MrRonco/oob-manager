//go:build linux || darwin

package main

import "golang.org/x/sys/unix"

// processUmask makes every file the process creates owner-only: the database and its
// WAL/SHM (sealed secrets, token hashes, the audit log), backups and generated keys (plan
// 06 §3.1), whichever subcommand creates them. An explicit mode keeps only what the umask allows.
const processUmask = 0o077

// restrictUmask sets the process umask and returns the previous one.
func restrictUmask() int { return unix.Umask(processUmask) }

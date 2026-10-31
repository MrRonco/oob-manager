// Package firstrun prepares a store-style install (docs/plans/09-store-ready-install.md):
// a container started with only a data volume. It checks that the data directory is
// writable, generates the age identity, app keys and UI certificate there once, keeps
// the backup notice marker, and holds the one-time first-run setup code.
//
// Nothing here ever replaces a configured or mounted file: callers use it only for paths
// that config.yaml left out and whose mounted defaults are absent. Generated sets are
// built in a temporary directory and renamed into place, so a crash never leaves half a
// key set, and an existing set is reused, never rewritten.
package firstrun

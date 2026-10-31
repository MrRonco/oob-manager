// Package fleet owns one poller per configured BMC (docs/system_design.md §2).
//
// Each server has its own goroutine, its own per-cycle timeout and its own circuit
// breaker, so a dead or hanging BMC can never stall another server. Every poll builds
// a new immutable ServerState and publishes it with atomic.Pointer; readers (the UI and
// the JSON API) only ever load published values, through the Reader interface.
//
// Sensor readings of each poll are written to the history store (Config.Samples);
// internal/history rolls them up and prunes them.
package fleet

// Package metrics renders the Prometheus text exposition format (version 0.0.4) for
// GET /metrics (tech_doc §29). It is hand-written on the standard library: no
// client_golang (CLAUDE.md rule 10).
//
// Every value comes from data the app already holds: the poller's published snapshots,
// the fan lease table, the console brokers, the notification dispatcher and in-process
// counters. A scrape never contacts a BMC. Label values are sanitized and capped, and
// every per-server list is capped, so a misbehaving BMC cannot blow up cardinality.
package metrics

// Package history serves the sensor history (docs/tech_doc.md §39): the chart ranges and
// their plans (which tier serves which part of a range), bucket merging and summaries,
// the event markers drawn over a chart, the CSV export, and the Service that reads the
// store's read-only connection and runs the rollup and retention janitor on the writer.
//
// Nothing here talks to a BMC: the fleet's sampler writes the samples
// (fleet.HistorySamples), this package only reads and maintains them.
package history

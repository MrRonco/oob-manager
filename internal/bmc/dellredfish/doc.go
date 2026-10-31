// Package dellredfish extends the generic Redfish driver with Dell iDRAC knowledge:
// licence tier (LicenseService on iDRAC9; "unknown" plus the GraphicalConsole hint on
// iDRAC8), firmware versions from Dell inventory IDs, and the iDRAC8 legacy SEL and
// Lifecycle log paths. Read-only. See docs/tech_doc.md §3.
package dellredfish

// Package redfish is the generic, read-only Redfish driver (gofish). Every request is
// a GET with a timeout and a body cap, over TLS that trusts exactly the configured SPKI
// SHA-256 pin. See docs/tech_doc.md §3 and docs/security.md (S3).
package redfish

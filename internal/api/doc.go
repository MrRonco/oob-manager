// Package api serves the read-only JSON API v1 (docs/tech_doc.md §6) and the
// unauthenticated /healthz and /readyz probes.
//
// Every /api/v1 route needs an API bearer token (Authorization header only, never a
// query parameter). Tokens are read-only by type: the handler authorizes each route
// with authz.Authorize against the token principal, so no token can reach anything but
// the view actions. Errors are RFC 9457 Problem Details. Handlers only read published
// fleet snapshots; no request ever reaches a BMC.
package api

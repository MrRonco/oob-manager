// Package web is the HTTP base of oob-manager: TLS policy, server timeouts, security
// headers with a per-request CSP nonce, cross-origin protection for state-changing
// requests, request size/time limits and RFC 9457 Problem Details errors.
//
// Route handlers are added by later phases; they receive requests only after the chain
// built by NewHandler has run.
package web

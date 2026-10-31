// Package repopolicy holds tests that check repository policy rather than code:
// every Go module dependency and every vendored front-end asset is documented
// (CLAUDE.md rule 10, docs/tech_doc.md §2), the dependency bot and the tool pins
// keep the 14-day rule (docs/security.md §6), and the public tree carries no
// network details of a real install (CLAUDE.md rule 12). It has no non-test code.
package repopolicy

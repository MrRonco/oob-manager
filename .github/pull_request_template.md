<!--
Thanks for contributing. Security fixes for unpublished vulnerabilities go through a private
advisory first (SECURITY.md), not a public pull request.
This pull request is public: no IP addresses, host names, serials, MAC addresses or credentials.
-->

## What and why

<!-- What this changes, and the problem it solves. Link the issue: "Fixes #123". -->

## How it was tested

<!-- The tests you added, and what you ran (make check, make e2e-ui, make visual ...). Mock BMCs only. -->

## Checklist

- [ ] Tests written first and passing; `make check` is green locally.
- [ ] Documentation updated where behaviour changes (`deploy/README.md`, `docs/tech_doc.md`, `docs/security.md`).
- [ ] A user-facing entry in `CHANGELOG.md` under **Unreleased** (or this change is invisible to users).
- [ ] Every commit is signed off for the DCO (`git commit -s`, see `CONTRIBUTING.md`).
- [ ] No real BMC data, addresses, host names or secrets in code, fixtures, screenshots or docs.
- [ ] No new dependency, or it has a `docs/tech_doc.md` §2 row and its release is at least 14 days old.
- [ ] Visual changes: baseline updated with `make visual-update` and `[visual]` in the title.

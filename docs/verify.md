# Verifying a release

Every release is built by this repository's GitHub Actions workflow
[`release.yml`](../.github/workflows/release.yml) from a tagged commit that passed CI, and its last job runs the commands below, as
written here, against what it just published. It publishes:

| What | Where | How it is signed or attested |
|---|---|---|
| Multi-arch image (linux/amd64, linux/arm64) | `ghcr.io/mrronco/oob-manager:vX.Y.Z` and the moving minor tag `vX.Y` | Keyless cosign signature (Sigstore, GitHub OIDC); SLSA build provenance (GitHub attestation, pushed to the registry); an SPDX SBOM of the image as a cosign attestation; BuildKit provenance and SBOM attestations inside the image index |
| Binaries `oob-manager_X.Y.Z_linux_{amd64,arm64}.tar.gz` | the GitHub release | `checksums.txt` (SHA-256) and SLSA build provenance for each archive |
| SBOM `oob-manager.spdx.json` | the GitHub release | the same document is attested on the image: Syft's inventory of the built linux/amd64 image (the arm64 image holds the same packages for another architecture) |

Nothing is signed with a long-lived key: there is no public key to download. A signature is
valid only if Sigstore's certificate says it was made by `release.yml` in
`github.com/MrRonco/oob-manager` for that tag. Check that before you run an image, and run it
by **digest**, not by tag.

## What you need

- [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) v3. The release workflow runs these steps with v3.1.3 after every release.
- `jq` and `base64`, to read the SBOM.
- The [GitHub CLI](https://cli.github.com/) (`gh attestation verify`). It may ask you to sign in
  (`gh auth login`); any GitHub account works, and no access to this repository is needed.
- One way to read an image digest: `docker buildx imagetools`, `crane` or `skopeo`.

```bash
VERSION=vX.Y.Z                         # the release you are installing
REPO=MrRonco/oob-manager
IMAGE=ghcr.io/mrronco/oob-manager
```

## 1. Resolve the tag to a digest

```bash
docker buildx imagetools inspect "$IMAGE:$VERSION" | awk '/^Digest:/ {print $2}'
# or: crane digest "$IMAGE:$VERSION"
DIGEST=sha256:<the value printed above>
REF="$IMAGE@$DIGEST"
```

The digest is of the multi-arch index; signatures and attestations are attached to it, and
Docker picks the right platform from it.

## 2. Verify the signature

```bash
cosign verify "$REF" \
  --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

cosign checks the signature against the Fulcio certificate and the Rekor transparency log and
prints the verified payload. Any other workflow, repository, branch or tag fails, which is the
point: a copy pushed by someone else, or a build from an untagged commit, does not verify.

## 3. Verify the build provenance (SLSA)

```bash
gh attestation verify "oci://$REF" --repo "$REPO" \
  --signer-workflow "$REPO/.github/workflows/release.yml"
```

This checks the provenance GitHub Actions recorded for the image: which repository, workflow,
commit and runner built it. To read the commit it was built from:

```bash
gh attestation verify "oci://$REF" --repo "$REPO" --format json \
  | jq -r '.[0].verificationResult.statement.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit'
```

## 4. Verify and read the SBOM

```bash
cosign verify-attestation "$REF" --type spdxjson \
  --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  | jq -r '.payload' | base64 -d | jq '.predicate.packages | length'
```

It lists what Syft found in the built image (linux/amd64), not in the source tree. The same SPDX document is attached to the GitHub release as `oob-manager.spdx.json`. The image
index also carries BuildKit's own provenance and SBOM attestations, readable with
`docker buildx imagetools inspect "$REF" --format '{{ json .Provenance }}'` (and `.SBOM`); they
are unsigned and informational, the checks above are the ones to rely on.

## 5. Run it by digest

```yaml
services:
  oob-manager:
    image: ghcr.io/mrronco/oob-manager@sha256:<the verified digest>
```

Upgrading means repeating steps 1 to 4 for the new tag and changing the digest; see
[deploy/README.md](../deploy/README.md), "Upgrade".

## Binaries

```bash
gh release download "$VERSION" --repo "$REPO" --dir "oob-$VERSION"
cd "oob-$VERSION"
sha256sum -c checksums.txt
for f in oob-manager_*_linux_*.tar.gz; do
  gh attestation verify "$f" --repo "$REPO" --signer-workflow "$REPO/.github/workflows/release.yml"
done
```

On macOS use `shasum -a 256 -c checksums.txt`. The checksums only catch a damaged or
incomplete download: anyone who could replace an archive could replace `checksums.txt` too.
Authenticity comes from the provenance check in the loop, which ties each archive to
`release.yml` in this repository. The archives hold one static binary each. The container image is the supported way to run
it; the binary is for building your own image or for inspection.

## If a check fails

Do not run the image. Check that `VERSION` matches the tag exactly and that `REPO` is
`MrRonco/oob-manager`, then open an issue. If you think a release was tampered with, report it
privately instead ([SECURITY.md](../SECURITY.md)).

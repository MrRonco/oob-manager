# oob-manager image: static Go binary on distroless (no shell, no package manager).
#
# Both base images are pinned by the digest of their multi-arch index, resolved from the
# registry API on 2026-10-20. Renovate (renovate.json) proposes tag + digest bumps once a
# release is >= 14 days old (CLAUDE.md rule 10); a digest whose registry gives no release
# timestamp stays pending on its Dependency Dashboard and is bumped by hand. Never use a
# floating tag. To re-resolve by hand:
#   curl -sI -H 'Accept: application/vnd.oci.image.index.v1+json' \
#     https://gcr.io/v2/distroless/static-debian12/manifests/nonroot | grep -i digest
#   (Docker Hub needs a token first: auth.docker.io/token?service=registry.docker.io&scope=repository:library/golang:pull)
#
# No "# syntax=" line on purpose: it would pull an unpinned frontend image.

# ---- build ----------------------------------------------------------------------------
FROM golang:1.27.3@sha256:957861185dbf29d93668ace41e011d091c6e779953d47f0316ef2cc58e28fe2b AS build

WORKDIR /src
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly

# Module files first so the download layer caches across source edits.
# go.sum* is a glob because the skeleton has no dependencies yet.
COPY go.mod go.sum* ./
RUN go mod download && go mod verify

COPY cmd/ cmd/
COPY internal/ internal/
COPY LICENSE NOTICE ./

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
# REPO_URL feeds the About page links (main.repoURL); empty hides them.
ARG REPO_URL=
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
      -trimpath -buildvcs=false \
      -ldflags="-s -w -X main.version=${VERSION} -X main.repoURL=${REPO_URL}" \
      -o /out/oob-manager ./cmd/oob-manager

# ---- runtime --------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG VERSION=dev
LABEL org.opencontainers.image.title="oob-manager" \
      org.opencontainers.image.description="Out-of-band management console for Dell iDRAC 8/9 and Redfish BMCs" \
      org.opencontainers.image.source="https://github.com/MrRonco/oob-manager" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0"

# COPY keeps the build output mode (0755) and owner root, so the runtime user cannot
# modify the binary; the rootfs is also mounted read-only by deploy/compose.yaml.
# No --chmod/--platform=$BUILDPLATFORM: both need BuildKit, and the image must stay
# buildable by the legacy builder some Docker hosts still use.
COPY --from=build /out/oob-manager /usr/local/bin/oob-manager
# The image is a binary distribution: it carries the licence and the third-party notices.
COPY --from=build /src/LICENSE /src/NOTICE /usr/share/doc/oob-manager/

# 65532 = distroless "nonroot". Numeric so runtimes can verify non-root without /etc/passwd.
USER 65532:65532
EXPOSE 8443

# Exec form: there is no shell in this image. The subcommand GETs
# https://127.0.0.1:8443/healthz with a 3 s timeout and exits 0/1.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/oob-manager", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/oob-manager"]
CMD ["serve"]

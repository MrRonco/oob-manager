# oob-manager — developer targets. `make check` is the local equivalent of CI.
GO      ?= go
PKGS    := ./...
COVER   := 80
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= oob-manager
# REPO_URL (https://…) is shown as Source/Docs links on the About page; empty hides them.
REPO_URL ?=
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.repoURL=$(REPO_URL)

# Tool pins. Bumps wait >= 14 days after upstream release (CLAUDE.md rule 10).
# Renovate tracks every pin through the "# renovate:" line above it (renovate.json);
# internal/repopolicy fails on a pin without one or on a Makefile/ci.yml mismatch.
# Keep in step with .github/workflows/ci.yml.
# renovate: datasource=go depName=github.com/golangci/golangci-lint/v2
GOLANGCI_VERSION    := v2.14.0
# renovate: datasource=go depName=golang.org/x/vuln
GOVULNCHECK_VERSION := v1.8.0
# actionlint: workflow linter, run with `go run` (not a module dependency).
# renovate: datasource=go depName=github.com/rhysd/actionlint
ACTIONLINT_VERSION  := v1.7.12
# bats for the host-side lease reader (deploy/host), run through npx; test only.
# renovate: datasource=npm depName=bats
BATS_VERSION        := 1.13.0

.PHONY: build test cover soak fuzz vet noexec lint actionlint vulncheck vuln docker image scan check e2e e2e-go e2e-ui e2e-bin dev host-test cut-test
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o bin/oob-manager ./cmd/oob-manager

test:
	$(GO) test -race -count=1 -timeout 20m $(PKGS)

# Nightly in CI (.github/workflows/nightly.yml): three runs in a random order with the
# race detector. Replay a failure with -shuffle=<seed printed in the log>.
soak:
	$(GO) test -race -count=3 -shuffle=on -timeout 30m $(PKGS)

# Fuzz targets (plan 06 §3.5), run nightly in two parallel sets (nightly.yml). Every
# `func Fuzz…` in the tree must be listed in exactly one set (internal/repopolicy).
# `make fuzz FUZZ_SET=A FUZZTIME=2m` for a longer local run; a crasher is written to the
# package's testdata/fuzz/<Target>/ and must be committed with its fix.
FUZZTIME ?= 30s
FUZZ_SET ?= all
FUZZ_A := ./internal/console/rfb:FuzzRFBFilter ./internal/console/rfb:FuzzRFBServerHandshake \
          ./internal/console/rfb:FuzzParseVersion ./internal/console:FuzzSerialControl \
          ./internal/console:FuzzSerialInput ./internal/fan/hostlease:FuzzLeaseAck \
          ./internal/audit:FuzzRedact ./internal/audit:FuzzGELFEncode \
          ./internal/netpolicy:FuzzCheckBMCAddr ./internal/firstrun:FuzzSetupCode
FUZZ_B := ./internal/bmc/redfish:FuzzLogEntryDecode ./internal/bmc/redfish:FuzzSnapshotDecode \
          ./internal/firmware:FuzzCompareVersions ./internal/web/ui:FuzzLinkify \
          ./internal/firmware/catalog/dell:FuzzParseCatalog ./internal/firmware/catalog/dell:FuzzVerifyArmored \
          ./internal/firmware/catalog/dell:FuzzPGPVerify ./internal/firmware/catalog/dell:FuzzParsePackets \
          ./internal/firmware/catalog/dell:FuzzUTF16Reader ./internal/csvx:FuzzField
FUZZ_TARGETS = $(if $(filter A,$(FUZZ_SET)),$(FUZZ_A),$(if $(filter B,$(FUZZ_SET)),$(FUZZ_B),$(FUZZ_A) $(FUZZ_B)))

fuzz:
	@set -e; for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; name=$${t##*:}; echo "== $$name ($$pkg)"; \
		$(GO) test $$pkg -run '^$$' -fuzz "^$$name\$$" -fuzztime $(FUZZTIME); \
	done

# Coverage gates (internal/covergate, stdlib only): the module total AND every package
# with statements must each be >= $(COVER) %, so a new package is gated automatically.
# COVER_REQUIRED must be present in the profile (CLAUDE.md rule 1 plus the packages that
# gained security controls since, plan 06 §3.9), so a rename cannot drop one silently.
# COVER_EXCLUDE is reported but not gated: in-repo test doubles, never linked into the
# binary. The profile is written WITHOUT -coverpkg, so each package's figure is its own
# tests' coverage of it; adding -coverpkg would change what the gate measures.
MODULE         := $(shell $(GO) list -m)
COVER_REQUIRED := internal/auth internal/authz internal/fan internal/power internal/audit \
                  internal/console internal/console/rfb internal/netpolicy \
                  internal/secrets/credstore internal/tofu internal/registry internal/firstrun
COVER_EXCLUDE  := internal/bmc/redfishmock internal/bmc/bmcssh/sshtest internal/console/rfbtest \
		internal/firmware/catalog/catalogtest

cover:
	$(GO) test -race -count=1 -timeout 20m -covermode=atomic -coverprofile=cover.out $(PKGS)
	@$(GO) run ./internal/covergate -profile cover.out -min $(COVER) -module $(MODULE) \
		-exclude "$(COVER_EXCLUDE)" $(COVER_REQUIRED)

vet:
	$(GO) vet $(PKGS)
	$(GO) vet -tags e2e ./cmd/oob-manager

# Hard rule 2: no shell-outs anywhere in the codebase (golangci depguard/forbidigo
# enforce the same rule; this grep works without any tool installed).
noexec:
	@! grep -rn --include='*.go' '"os/exec"' cmd internal || (echo 'os/exec is forbidden (CLAUDE.md rule 2)'; exit 1)

# Runs golangci-lint when installed; otherwise warns and succeeds so `make check`
# stays usable on a bare machine. CI always runs the linter.
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run $(PKGS); \
	else \
		echo "WARNING: golangci-lint not installed; lint SKIPPED."; \
		echo "  Install (pinned): go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)"; \
		echo "  Or run once:      go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION) run ./..."; \
	fi

# Reachability-aware vulnerability scan, pinned via `go run` (no global install).
vulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) $(PKGS)

vuln: vulncheck

# Lints .github/workflows (expressions, action inputs, job graph). actionlint shellchecks
# every run: script only when shellcheck is on PATH: locally that half is skipped
# silently without it; CI asserts shellcheck is installed first, so there it fails closed.
actionlint:
	$(GO) run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

docker:
	@command -v docker >/dev/null 2>&1 || (echo "docker not installed; build the image on a Docker host (see deploy/README.md)"; exit 1)
	docker build --build-arg VERSION=$(VERSION) --build-arg REPO_URL=$(REPO_URL) -t $(IMAGE):$(VERSION) .

image: docker

# Same gate as CI: fail on fixable HIGH/CRITICAL findings.
scan:
	trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 $(IMAGE):$(VERSION)

check: vet noexec lint actionlint test cover

# Host-side fan lease reader (bash + awk, deploy/host). Needs node/npx; installs nothing globally.
host-test:
	npx --yes bats@$(BATS_VERSION) deploy/host/test

# Release cut script (scripts/public-cut.sh, plan 07 §4.6): bats tests in a temp repo with
# stub scanners (no Docker, no network, no real tag), then shellcheck when installed.
cut-test:
	npx --yes bats@$(BATS_VERSION) scripts/test
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck -x scripts/public-cut.sh && shellcheck -s bash scripts/test/public-cut.bats; \
	else \
		echo "WARNING: shellcheck not installed; shellcheck SKIPPED."; \
	fi

# --- End to end (mock BMCs only; nothing here contacts a real BMC) -------------------
# The harness lives in cmd/oob-manager behind the `e2e` build tag: two redfishmock
# servers (iDRAC8 R730XD, iDRAC9 R240 fixtures) over TLS, a temp install, an admin
# bootstrapped through the real CLI and the real `serve` command, all in-process.
E2E_BIN  := bin/e2e.test
E2E_PORT ?= 18443
# CI sets PW_INSTALL_FLAGS=--with-deps (installs the browser's system libraries).
PW_INSTALL_FLAGS ?=
DEV_ADDR ?= 127.0.0.1:8443

e2e: e2e-go e2e-ui

e2e-go:
	$(GO) test -tags e2e -race -count=1 -run '^(TestE2E|TestShowcaseHarness)$$' ./cmd/oob-manager

e2e-bin:
	$(GO) test -tags e2e -c -o $(E2E_BIN) ./cmd/oob-manager

# Playwright smoke (login -> TOTP -> overview screenshot in tests/e2e/test-results/).
# PW_ARGS picks spec files (e.g. "pages.spec.ts"); OOB_E2E_IGNORE (env) skips some (see ci.yml).
PW_ARGS ?=
e2e-ui: e2e-bin
	cd tests/e2e && npm ci --no-audit --no-fund && npx playwright install $(PW_INSTALL_FLAGS) chromium && \
		OOB_E2E_PORT=$(E2E_PORT) npx playwright test $(PW_ARGS)

# Runs the app against the mocks until Ctrl-C. Prints the URL, the sign-in file (temp
# dir, 0600, deleted on exit) and a fresh TOTP code every 30 s.
dev: e2e-bin
	OOB_DEV=1 OOB_DEV_LISTEN=$(DEV_ADDR) ./$(E2E_BIN) -test.run '^TestDevServer$$' -test.timeout 0

# --- README screenshots (tests/e2e/README.md "README screenshots") --------------------
# showcase.spec.ts against the dev server in showcase mode (OOB_DEV_SHOWCASE=1, see
# cmd/oob-manager/e2e_showcase_harness_test.go): docs/screenshots/<name>-{light,dark}.png
# and social-preview.png, then pngquant + oxipng. Fails early without those two tools
# unless SHOWCASE_RAW=1 (raw PNGs for a local look; never commit them). The committed
# images come from the "showcase" workflow (.github/workflows/showcase.yml).
# The footer of every shot shows SHOWCASE_VERSION (default: the latest tag), stamped into
# a separate harness build; in a test binary the package path, not "main", names it.
SHOWCASE_DIR     ?= docs/screenshots
SHOWCASE_RAW     ?=
SHOWCASE_VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null)
SHOWCASE_BIN     := bin/e2e-showcase.test

.PHONY: showcase
showcase:
	@test -n "$(SHOWCASE_VERSION)" || { echo "No git tag found: set SHOWCASE_VERSION=vX.Y.Z (the version in the screenshots' footer)."; exit 1; }
	SHOWCASE_RAW=$(SHOWCASE_RAW) bash tests/e2e/showcase/optimise.sh --check
	$(GO) test -tags e2e -c -o $(SHOWCASE_BIN) -ldflags "-X $(MODULE)/cmd/oob-manager.version=$(SHOWCASE_VERSION)" ./cmd/oob-manager
	OOB_SHOWCASE_WANT_VERSION=$(SHOWCASE_VERSION) ./$(SHOWCASE_BIN) -test.run '^TestShowcaseVersion$$'
	rm -f $(SHOWCASE_DIR)/*.png
	cd tests/e2e && npm ci --no-audit --no-fund && npx playwright install $(PW_INSTALL_FLAGS) chromium && \
		OOB_SHOWCASE=1 OOB_E2E_BIN=../../$(SHOWCASE_BIN) OOB_E2E_PORT=$(E2E_PORT) npx playwright test showcase.spec.ts
	SHOWCASE_RAW=$(SHOWCASE_RAW) bash tests/e2e/showcase/optimise.sh $(SHOWCASE_DIR)

# --- ZAP (plan 06 §3.2) ---------------------------------------------------------------
# Passive baseline of the unauthenticated pages on every CI run (zap-quick); the
# authenticated baseline plus the API scan of docs/api/openapi.yaml nightly (zap-full).
# Linux + Docker only (tests/zap/run.sh). Allowlists: tests/zap/rules.tsv, api-rules.tsv.
# Image: zap-stable 20261008 (ZAP weekly-stable of 2026-10-08, >= 14 days old when pinned,
# rule 10), pinned by its multi-arch index digest; Renovate updates tag and digest together.
ZAP_IMAGE   ?= zaproxy/zap-stable:20261008@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2
ZAP_PORT    ?= 18443
ZAP_OUT     ?= tests/zap/reports

zap-quick: e2e-bin
	ZAP_IMAGE=$(ZAP_IMAGE) BIN=./$(E2E_BIN) PORT=$(ZAP_PORT) OUT=$(ZAP_OUT) bash tests/zap/run.sh quick

zap-full: e2e-bin
	ZAP_IMAGE=$(ZAP_IMAGE) BIN=./$(E2E_BIN) PORT=$(ZAP_PORT) OUT=$(ZAP_OUT) bash tests/zap/run.sh full

# --- Visual baseline (plan 04 §3; policy in tests/e2e/README.md) -----------------------
# visual.spec.ts runs only inside the pinned Playwright image (linux/amd64), the one
# place where the PNGs in tests/e2e/visual-baseline/ are valid: font rasterising and the
# fallback fonts differ per OS. Needs Docker; CI's `visual` job runs the same targets.
# The harness is a static linux/amd64 build, so the image needs no Go toolchain.
# Image: Playwright 1.63.0, noble, pinned by its multi-arch index digest (always run with
# --platform linux/amd64), built 2026-09-04 (>= 14 days old when pinned, rule 10).
# Renovate updates tag and digest together with @playwright/test (one "Playwright" PR),
# and internal/repopolicy fails if the tag and tests/e2e/package-lock.json disagree.
PW_IMAGE    ?= mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27
VISUAL_BIN  := bin/e2e-linux-amd64.test
VISUAL_ARGS ?=

.PHONY: visual visual-update visual-bin zap-quick zap-full
visual-bin:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) test -tags e2e -c -o $(VISUAL_BIN) ./cmd/oob-manager

# The container sees the repository read-only; only tests/e2e is writable (node_modules,
# test-results, visual-baseline). No capabilities, no privilege gain, a non-root user;
# a 1 GB /dev/shm for Chromium instead of sharing the host's IPC namespace. Neither
# dependency needs install scripts (the image already holds the browsers).
visual: visual-bin
	@command -v docker >/dev/null 2>&1 || { \
		echo "make visual needs Docker: the baseline is only valid inside $(PW_IMAGE)."; \
		echo "Without Docker, run the CI workflow by hand (Actions > ci > Run workflow, visual_update=true)"; \
		echo "and commit the visual-baseline artifact it uploads, in a PR titled with [visual]."; exit 1; }
	docker run --rm --platform linux/amd64 --shm-size=1gb --cap-drop=ALL --security-opt no-new-privileges \
		--user "$$(id -u):$$(id -g)" \
		-e HOME=/tmp -e npm_config_cache=/tmp/.npm -e CI \
		-e OOB_VISUAL=1 -e OOB_E2E_BIN=/work/$(VISUAL_BIN) -e OOB_E2E_PORT=$(E2E_PORT) \
		-v "$(CURDIR)":/work:ro -v "$(CURDIR)/tests/e2e":/work/tests/e2e \
		-w /work/tests/e2e $(PW_IMAGE) \
		sh -c 'npm ci --ignore-scripts --no-audit --no-fund && npx playwright test visual.spec.ts $(VISUAL_ARGS)'

# Rewrites every baseline PNG, then compares once more against what it just wrote, so a
# non-deterministic page fails here instead of in the next PR.
visual-update:
	$(MAKE) visual VISUAL_ARGS=--update-snapshots=all
	$(MAKE) visual VISUAL_ARGS=--update-snapshots=none

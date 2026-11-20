# Works with GNU make on Linux, macOS and Windows (Git Bash sh).

PKG     ?= ./...
# Per-package test timeout, set so a slow package fails with a clear message.
# Each package should finish in under half of it, -race included (#203).
TEST_TIMEOUT ?= 10m
MODULE  := github.com/sneakercreepers/creep
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILDINFO := $(MODULE)/internal/buildinfo
# Characters allowed in version and commit; anything else is dropped so a tag
# name can never break out of the -ldflags quoting.
SAFE_CHARS := A-Za-z0-9._+-

ifeq ($(OS),Windows_NT)
EXE := .exe
endif
BIN := bin/creep$(EXE)

.PHONY: build test check fmt-check tidy vet budget map map-check protections rulesets clean

# VERSION and COMMIT reach the recipe through the environment, never as shell
# text, and are filtered to SAFE_CHARS before use.
build: export CREEP_VERSION = $(VERSION)
build: export CREEP_COMMIT = $(COMMIT)
build:
	@v="$$(printf '%s' "$$CREEP_VERSION" | tr -cd '$(SAFE_CHARS)')"; \
	c="$$(printf '%s' "$$CREEP_COMMIT" | tr -cd '$(SAFE_CHARS)')"; \
	set -x; go build -trimpath -ldflags "-s -w -X $(BUILDINFO).version=$${v:-dev} -X $(BUILDINFO).commit=$${c:-unknown}" -o $(BIN) ./cmd/creep

test:
	go test -timeout $(TEST_TIMEOUT) $(PKG)

check: fmt-check tidy vet budget map-check
	@# -race needs cgo; Go disables cgo when no C compiler is found (common on Windows).
	@if [ "$$(go env CGO_ENABLED)" = "1" ]; then \
		echo "go test -race -timeout $(TEST_TIMEOUT) ./..."; go test -race -timeout $(TEST_TIMEOUT) ./...; \
	else \
		echo "cgo disabled: running go test ./... without -race"; go test -timeout $(TEST_TIMEOUT) ./...; \
	fi

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

# Fails when go.mod or go.sum differ from what go mod tidy would write, so a
# used dependency cannot hide behind a stale // indirect comment.
tidy:
	go mod tidy -diff

vet:
	go vet ./...

# Dependency allowlist, network/exec import rules, architecture layer table,
# non-Go sources and workspace files, module and binary caps, file length,
# workflow pinning, agent-loop policy phrases.
budget:
	go run ./internal/tools/budget

# docs/map.md: every package with its doc.go first sentence and its layer.
map:
	go run ./internal/tools/pkgmap

# Fixed protections (#17): one test per protection, each with a broken fixture
# that proves it can fail, and the holistic --replay run (architecture.md §9).
# make check runs them too; CI runs this target as the required protections job,
# with a bounded fuzz run on top. internal/tools/budget checks every name exists.
PROTECTION_TESTS := FuzzScanSendsNoSecret|TestScanProtectionsCatchBrokenPath|TestScanSendsOnlyRedactedFragments|FuzzRedactSecrets|FuzzFile|TestEveryCallLogged|TestToolCanaryProtection|TestInputCarriesNoText|TestTextCapableCatchesText|TestNetImportFailsBudget|TestHolisticReplayProtections|TestHolisticCatchesBrokenRun|TestEveryContainerIsHardened|TestHardeningCheckCatchesWeakenedRun|TestMountRefusesHostPaths|TestOperatorProxiesNeverReachContainers|TestRunRefusesImageVolumes|TestCanaryLeakAbortsRun|TestNoPortPublished|TestDatabaseMountsNoHostPath|TestBuildIsOffline|TestBuildCheckCatchesWeakenedBuild|TestBuildRefusesEscapes|TestBuildContextLeavesSecretsOut|TestDockerfileBypassesRefused|TestStageReferencesOnlyEarlierStages|FuzzCheckDockerfile|TestOracleCatchesOldCheck|TestHasOnBuild|TestBaseImageProblem|TestModelCannotLowerRisk|TestModelCannotRemoveCandidate|TestMissingCanaryIsIncomplete|TestCanaryNeverReachesResult|TestTripwireRecall|TestMissedCanaryIsIncomplete|TestModelOutputNeverLowersCandidates|TestScanEvaluatesAnyLanguage
PROTECTION_PKGS  := ./internal/gateway ./internal/redact ./internal/models ./internal/planner ./internal/discover ./internal/tools/budget ./internal/cli ./internal/sandbox
FUZZTIME ?= 30s
protections:
	go test -count=1 -run '^($(PROTECTION_TESTS))$$' $(PROTECTION_PKGS)
	go test -run '^$$' -fuzz '^FuzzScanSendsNoSecret$$' -fuzztime $(FUZZTIME) ./internal/gateway

# Fails when docs/map.md differs from what make map would write.
map-check:
	go run ./internal/tools/pkgmap -check

# Creates or updates each ruleset in .github/rulesets (file name = ruleset name),
# then applies .github/settings, so re-running after a reviewed change is safe.
# Needs gh authenticated as an admin.
REPO ?= sneakercreepers/creep
rulesets: repo-settings
	@for f in .github/rulesets/*.json; do \
		name="$$(basename "$$f" .json)"; \
		id="$$(gh api "repos/$(REPO)/rulesets" --jq ".[] | select(.name == \"$$name\") | .id")" || exit 1; \
		if [ -n "$$id" ]; then \
			echo "update $$name ($$id)"; gh api -X PUT "repos/$(REPO)/rulesets/$$id" --input "$$f" >/dev/null || exit 1; \
		else \
			echo "create $$name"; gh api -X POST "repos/$(REPO)/rulesets" --input "$$f" >/dev/null || exit 1; \
		fi; \
	done

# The release environment only deploys v* tags. The tag policy is added only when
# missing because POSTing a duplicate fails.
repo-settings:
	@echo "update actions permissions"; gh api -X PUT "repos/$(REPO)/actions/permissions" --input .github/settings/actions-permissions.json >/dev/null
	@echo "update environment release"; gh api -X PUT "repos/$(REPO)/environments/release" --input .github/settings/release-environment.json >/dev/null
	@n="$$(gh api "repos/$(REPO)/environments/release/deployment-branch-policies" --jq '[.branch_policies[] | select(.name == "v*" and .type == "tag")] | length')" || exit 1; \
	if [ "$$n" = 0 ]; then \
		echo "add tag policy v*"; gh api -X POST "repos/$(REPO)/environments/release/deployment-branch-policies" -f name='v*' -f type=tag >/dev/null || exit 1; \
	fi

clean:
	rm -f bin/creep bin/creep.exe coverage.out

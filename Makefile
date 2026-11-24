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

.PHONY: build test check fmt-check lint tidy vet test386 budget map map-check protections rulesets repo-settings repo-settings-check clean

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

check: fmt-check lint tidy vet test386 budget map-check
	@# -race needs cgo; Go disables cgo when no C compiler is found (common on Windows).
	@if [ "$$(go env CGO_ENABLED)" = "1" ]; then \
		echo "go test -race -timeout $(TEST_TIMEOUT) ./..."; go test -race -timeout $(TEST_TIMEOUT) ./...; \
	else \
		echo "cgo disabled: running go test ./... without -race"; go test -timeout $(TEST_TIMEOUT) ./...; \
	fi

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

# CI lint is the required gate; running it here too catches a lint failure,
# such as the gocognit ratchet (#136), before the PR. Skipped, with a note,
# where golangci-lint is not installed (the CI test job).
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "golangci-lint run ./..."; golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed: skipped; CI lint runs it"; \
	fi

# Fails when go.mod or go.sum differ from what go mod tidy would write, so a
# used dependency cannot hide behind a stale // indirect comment.
tidy:
	go mod tidy -diff

# GOARCH=386 keeps 32-bit builds compilable: an untyped constant above
# 2^31-1 in an int position fails there and nowhere else (#145).
vet:
	go vet ./...
	GOARCH=386 go vet ./...

# Runs the packages whose bounds depend on int width as 32-bit binaries:
# vet compiles them but cannot catch an int conversion that wraps at run
# time (a hostile git index count, a budget limit). amd64 Linux and Windows
# run 386 binaries natively; cgo is off, as cross builds need.
test386:
	CGO_ENABLED=0 GOARCH=386 go test -timeout $(TEST_TIMEOUT) ./internal/gitindex/ ./internal/gateway/

# Dependency allowlist, network/exec import rules, architecture layer table,
# non-Go sources and workspace files, module and binary caps, file length,
# workflow pinning, agent-loop policy phrases.
budget:
	go run ./internal/tools/budget
	go run ./internal/tools/linkcheck

# docs/map.md: every package with its doc.go first sentence and its layer.
map:
	go run ./internal/tools/pkgmap

# Fixed protections (#17): one test per protection, each with a broken fixture
# that proves it can fail, and the holistic --replay run (architecture.md §9).
# make check runs them too; CI runs this target as the required protections job,
# with a bounded fuzz run on top. internal/tools/budget checks every name exists.
PROTECTION_TESTS := FuzzScanSendsNoSecret|TestScanProtectionsCatchBrokenPath|TestScanSendsOnlyRedactedFragments|FuzzRedactSecrets|FuzzFile|TestEveryCallLogged|TestToolCanaryProtection|TestInputCarriesNoText|TestTextCapableCatchesText|TestTextGuardsMatch|TestSignalCarriesNoText|TestNetImportFailsBudget|TestHolisticReplayProtections|TestHolisticCatchesBrokenRun|TestEveryContainerIsHardened|TestHardeningCheckCatchesWeakenedRun|TestMountRefusesHostPaths|TestOperatorProxiesNeverReachContainers|TestRunRefusesImageVolumes|TestCanaryLeakAbortsRun|TestNoPortPublished|TestDatabaseMountsNoHostPath|TestBuildIsOffline|TestBuildCheckCatchesWeakenedBuild|TestBuildRefusesEscapes|TestBuildContextLeavesSecretsOut|TestDockerfileBypassesRefused|TestStageReferencesOnlyEarlierStages|FuzzCheckDockerfile|TestOracleCatchesOldCheck|TestHasOnBuild|TestBaseImageProblem|TestBuildFailureNeverFailsScan|TestBuildUsesScanFiles|TestBuildOnlyWhenEnabled|TestCtrlCClosesTheSandbox|TestCtrlCWhileStagingIsInterrupted|TestVerificationReasonsClosed|TestModelCannotLowerRisk|TestModelCannotRemoveCandidate|TestMissingCanaryIsIncomplete|TestCanaryNeverReachesResult|TestTripwireRecall|TestMissedCanaryIsIncomplete|TestModelOutputNeverLowersCandidates|TestScanEvaluatesAnyLanguage|TestExchangeRunsOnlyInRunner|TestRunnerAnswerCannotBeForged|TestInvalidPoCRejectedBeforeRun|TestModelCannotPickHost|FuzzBuiltRequestStaysOnApp|TestOraclesCannotBeFaked|TestStatusNeverVerifies|TestRunsAreIndependent|TestAppCanaryPlanted|TestNoTransportSeamExported|TestLeakGuardCatchesEveryShape|TestSendWithoutConsent|TestUnknownHeaderRefused|TestPromptDeadline|TestStoreDirMustBePlain|TestStoreDirCheckedOnRead|TestRelativeStorePathRefused|TestInCI|TestNoVerifiedFromZeroRuns|TestBundleIsScrubbed|TestPoCRateChecked|TestZeroRunsStayProbable|TestBundleHoldsNoSecret|TestReproduceNeedsNoModel|TestBundleMasksSessions|FuzzMaskCredentials|TestPoCReplayMissStops|TestFingerprintGolden|TestBaselineFileRejectsHostile|TestBaselineErrorsQuoteNoValue|TestBaselineSuppressesOnlyExactLiveMatch|TestBaselineWriteNeedsFullRun|TestSuppressionChecked|TestSuppressionInEveryFormat|TestReadJSONChecksSuppression|TestScanRefusesHostileBaseline|TestBaselineNeverHidesIncomplete|TestBaselineLinkRefused|TestAcceptRefuses|TestSliceSinkIsRedactedSinkLine|TestAnchorIgnoresLine|TestBaselineDirLinkRefused|TestBaselineDevicePathRefused|TestBaselineWriteRefusesIncremental|TestBaselineSpecialFileRefused|TestActionStandIn|TestPreflightPolicy|TestInstallVerifiesBeforeUse|TestScanRecordsExitCodeAndReports|TestScanPullRequest|TestScanMergeGroupBaseline|TestCommentBody|TestVerdict|TestActionRunsOnlyItsScripts|TestPRModeNeverWaitsForVerification|TestNightlyNeverPassesUnverified|TestNightlyNeverLooserThanPR|TestProjectFileCannotLoosenNightlyGate|TestUnverifiedGateNeverLoosens|TestProjectCannotLoosenTheModeGate|TestScanWorkingDirectoryScope|TestRedactPasswordShapesPentest|TestSplitImageCheckedWhole|TestDockerfileOutsideFormRefused|TestDockerfileAllowlistIsClosed|TestBuildUsesCheckedDockerfile|TestPlanBuildRefuses|TestRecipeTextNeverReachesPlanner|TestRecipeGuardCatchesBrokenPath|TestFailingFixturesRefused|TestHostileHintStaysData|TestStabilityNeverDropsCandidates|TestStabilityNeverLowersRisk|TestStabilityReplayIsDeterministic|TestStabilityChecked|TestReadJSONChecksStability|TestTamperedRecipeFailsScan|TestRecipePolicyAllowlist|TestProjectFileCannotAddRecipeSources|TestScanIgnoresRepositoryRecipes|TestParseLockRefuses|TestVerifyRefusesTampering|TestRecipeAddRefuses|TestBuildMirrorConfined|TestBuildMirrorRefused|TestBuildMirrorKeepsChecks|TestProjectCannotSetBuildMirror|TestMirrorRulesMatchConfig|TestMCPWritesOnlyUnderCreep|TestMCPStartsNoContainer|TestMCPRefusesHostileArguments|TestLinkReachCatchesNet|TestSDKUsesAllowlisted|TestLoadVerifiesEveryPin|TestCloudBenchPublishesNoEndpointOrReplies
PROTECTION_PKGS  := ./internal/gateway ./internal/config ./internal/redact ./internal/models ./internal/planner ./internal/reader ./internal/discover ./internal/tools/budget ./internal/cli ./internal/sandbox ./internal/verify ./internal/report ./internal/baseline ./internal/scanrun ./internal/tools/actionscripts ./internal/recipe ./internal/mcp ./internal/tools/linkcheck ./internal/recipestore ./internal/tools/benchgate
FUZZTIME ?= 30s
protections:
	go test -count=1 -run '^($(PROTECTION_TESTS))$$' $(PROTECTION_PKGS)
	go test -run '^$$' -fuzz '^FuzzScanSendsNoSecret$$' -fuzztime $(FUZZTIME) ./internal/gateway

# Fails when docs/map.md differs from what make map would write.
map-check:
	go run ./internal/tools/pkgmap -check

# Reports drift, applies .github/settings, creates or updates each ruleset in
# .github/rulesets (file name = ruleset name), then checks again, so a setting
# GitHub did not take fails the run. Re-running after a reviewed change is safe.
# Needs gh authenticated as an admin.
REPO ?= sneakercreepers/creep
rulesets:
	@rc=0; bash .github/scripts/settings-drift.sh "$(REPO)" || rc=$$?; [ "$$rc" -le 1 ] || exit "$$rc"
	@$(MAKE) --no-print-directory repo-settings
	@for f in .github/rulesets/*.json; do \
		name="$$(basename "$$f" .json)"; \
		id="$$(gh api "repos/$(REPO)/rulesets" --jq ".[] | select(.name == \"$$name\") | .id")" || exit 1; \
		if [ -n "$$id" ]; then \
			echo "update $$name ($$id)"; gh api -X PUT "repos/$(REPO)/rulesets/$$id" --input "$$f" >/dev/null || exit 1; \
		else \
			echo "create $$name"; gh api -X POST "repos/$(REPO)/rulesets" --input "$$f" >/dev/null || exit 1; \
		fi; \
	done
	@bash .github/scripts/settings-drift.sh "$(REPO)"

# The release environment only deploys v* tags: any other deployment policy
# fails the run before Actions settings change, and the tag policy is added
# only when missing because POSTing a duplicate fails. allowed_actions must be
# selected before the allowlist is accepted. immutable-releases.json records
# the expected state for the drift check; code never turns immutable releases off.
# bench-cloud, which holds the cloud bench key (#36), deploys only the main
# branch (a custom policy: main is protected by a ruleset, not classic branch
# protection) and needs the maintainer's approval.
repo-settings:
	@echo "update environment release"; gh api -X PUT "repos/$(REPO)/environments/release" --input .github/settings/release-environment.json >/dev/null
	@echo "update environment bench-cloud"; gh api -X PUT "repos/$(REPO)/environments/bench-cloud" --input .github/settings/bench-cloud-environment.json >/dev/null
	@extra="$$(gh api --paginate "repos/$(REPO)/environments/release/deployment-branch-policies" --jq '.branch_policies[] | select(.name != "v*" or .type != "tag") | "\(.type) \(.name)"')" || exit 1; \
	if [ -n "$$extra" ]; then \
		echo "environment release has deployment policies other than the v* tag; remove them in its settings:" >&2; \
		printf '%s\n' "$$extra" | LC_ALL=C tr -c '[:graph:]\n' ' ' >&2; exit 1; \
	fi
	@n="$$(gh api "repos/$(REPO)/environments/release/deployment-branch-policies" --jq '[.branch_policies[] | select(.name == "v*" and .type == "tag")] | length')" || exit 1; \
	if [ "$$n" = 0 ]; then \
		echo "add tag policy v*"; gh api -X POST "repos/$(REPO)/environments/release/deployment-branch-policies" -f name='v*' -f type=tag >/dev/null || exit 1; \
	fi
	@extra="$$(gh api --paginate "repos/$(REPO)/environments/bench-cloud/deployment-branch-policies" --jq '.branch_policies[] | select(.name != "main" or .type != "branch") | "\(.type) \(.name)"')" || exit 1; \
	if [ -n "$$extra" ]; then \
		echo "environment bench-cloud has deployment policies other than the main branch; remove them in its settings:" >&2; \
		printf '%s\n' "$$extra" | LC_ALL=C tr -c '[:graph:]\n' ' ' >&2; exit 1; \
	fi
	@n="$$(gh api "repos/$(REPO)/environments/bench-cloud/deployment-branch-policies" --jq '[.branch_policies[] | select(.name == "main" and .type == "branch")] | length')" || exit 1; \
	if [ "$$n" = 0 ]; then \
		echo "add branch policy main"; gh api -X POST "repos/$(REPO)/environments/bench-cloud/deployment-branch-policies" -f name=main -f type=branch >/dev/null || exit 1; \
	fi
	@echo "update actions permissions"; gh api -X PUT "repos/$(REPO)/actions/permissions" --input .github/settings/actions-permissions.json >/dev/null
	@echo "update allowed actions"; gh api -X PUT "repos/$(REPO)/actions/permissions/selected-actions" --input .github/settings/actions-selected.json >/dev/null
	@echo "update workflow permissions"; gh api -X PUT "repos/$(REPO)/actions/permissions/workflow" --input .github/settings/workflow-permissions.json >/dev/null
	@echo "enable immutable releases"; gh api -X PUT "repos/$(REPO)/immutable-releases" >/dev/null

# Read-only: reports every difference between .github/rulesets,
# .github/settings and the live repository; exits 1 on drift, 2 when a setting
# cannot be read. Not in make check: it needs an admin gh token CI does not have.
repo-settings-check:
	@bash .github/scripts/settings-drift.sh "$(REPO)"

clean:
	rm -f bin/creep bin/creep.exe coverage.out

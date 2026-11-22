#!/usr/bin/env bash
# Runs creep scan for the Action (ADR 0023) and records its exit code; the
# verdict step fails the job on it, after SARIF upload and the comment. On a
# pull request it scans only the changed files (--changed); on a pull request
# or a merge group it reads the baseline from the base commit, so the change
# under review cannot suppress its own findings. Writes exit-code and, for
# a run that wrote reports (exit 0, 1 or 4), report, sarif and markdown to
# $GITHUB_OUTPUT.
#
# Environment: CREEP, INPUT_CONFIG, INPUT_MODE, INPUT_BASELINE,
# INPUT_INCREMENTAL, INPUT_API_KEY, EVENT_NAME, BASE_SHA, NEED_SARIF,
# NEED_MARKDOWN (true|false each), RUNNER_TEMP. BASE_SHA is the pull
# request's or the merge group's base commit.
set -euo pipefail

fail() {
  echo "::error title=creep::$1"
  exit 1
}

args=(scan)

is_pull_request() { [ "${EVENT_NAME:-}" = pull_request ]; }

# A merge group holds queued pull requests not yet on the base branch, so
# its baseline comes from the base commit too.
reviews_a_change() { is_pull_request || [ "${EVENT_NAME:-}" = merge_group ]; }

# upload-sarif and comment are compared case-insensitively in action.yml's
# if:, so anything but true or false would skip a step without a word.
check_switch() {
  case "${2:-}" in
    true | false) ;;
    *) fail "$1 must be true or false" ;;
  esac
}

# The base commit must be in the clone: actions/checkout with fetch-depth: 2
# fetches the merge commit and both of its parents.
need_base() {
  [[ "${BASE_SHA:-}" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || fail "the event has no base commit SHA"
  git cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null ||
    fail "the base commit is not in the clone: check out with fetch-depth: 2 (or 0)"
}

# Repository-relative, plain characters, no empty, . or .. segment.
valid_repo_path() {
  [[ "$1" =~ ^[A-Za-z0-9_][A-Za-z0-9._/-]*$ ]] && [[ "$1" != *//* ]] && [[ ! "/$1/" =~ /\.\.?/ ]]
}

add_mode() {
  case "${INPUT_MODE:-}" in
    "") ;;
    pr | nightly) args+=("--mode=$INPUT_MODE") ;;
    *) fail "mode must be pr, nightly or empty" ;;
  esac
}

add_changed() {
  case "${INPUT_INCREMENTAL:-true}" in
    true) ;;
    false) return 0 ;;
    *) fail "incremental must be true or false" ;;
  esac
  is_pull_request || return 0
  need_base
  local list="$RUNNER_TEMP/creep-changed.txt"
  git diff --no-ext-diff --no-textconv --name-only -z "$BASE_SHA...HEAD" >"$list" ||
    fail "git diff against the base commit failed"
  args+=("--changed=$list")
}

add_baseline() {
  local path="${INPUT_BASELINE:-}" copy="$RUNNER_TEMP/creep-baseline.json"
  [ -n "$path" ] || return 0
  valid_repo_path "$path" || fail "baseline must be a plain repository-relative path"
  if ! reviews_a_change; then
    if [ ! -f "$path" ]; then
      echo "::notice title=creep::no $path in the checkout: scanning without a baseline"
      return 0
    fi
    args+=("--baseline=$path")
    return 0
  fi
  need_base
  if ! git cat-file -e "$BASE_SHA:$path" 2>/dev/null; then
    echo "::notice title=creep::the base commit has no $path: scanning without a baseline"
    return 0
  fi
  git cat-file blob "$BASE_SHA:$path" >"$copy" || fail "could not read $path from the base commit"
  args+=("--baseline=$copy")
}

# Adds key=<path> to outputs for a report creep wrote as a regular file,
# and fails when the Action needs a report that is missing.
outputs=()
add_report() {
  local key="$1" name="$2" needed="$3" path="$PWD/.creep/$2"
  if [ -f "$path" ] && [ ! -L "$path" ]; then
    outputs+=("$key=$path")
    return 0
  fi
  [ "$needed" = true ] || return 0
  fail "creep wrote no .creep/$name: keep it in report.formats (user file, --config or policy)"
}

# All or nothing: a failed check publishes no report.
publish_reports() {
  [ -d .creep ] && [ ! -L .creep ] || fail ".creep is not a directory creep wrote"
  add_report report report.json false
  add_report sarif report.sarif "${NEED_SARIF:-false}"
  add_report markdown report.md "${NEED_MARKDOWN:-false}"
  [ "${#outputs[@]}" -eq 0 ] || printf '%s\n' "${outputs[@]}" >>"$GITHUB_OUTPUT"
}

[ -n "${CREEP:-}" ] || fail "no creep binary"
check_switch upload-sarif "${NEED_SARIF:-}"
check_switch comment "${NEED_MARKDOWN:-}"
[ -z "${INPUT_CONFIG:-}" ] || args+=("--config=$INPUT_CONFIG")
add_mode
add_changed
add_baseline
if [ -n "${INPUT_API_KEY:-}" ]; then
  export CREEP_API_KEY="$INPUT_API_KEY"
fi
unset INPUT_API_KEY

set +e
"$CREEP" "${args[@]}"
code=$?
set -e
echo "exit-code=$code" >>"$GITHUB_OUTPUT"
case "$code" in
  0 | 1 | 4) publish_reports ;;
esac

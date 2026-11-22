#!/usr/bin/env bash
# Posts or updates the Action's one pull request comment (ADR 0023). The
# comment is found by the hidden marker at the start of its body, among the
# comments of the token's bot account only. The body is the marker, a
# verdict line picked from a fixed table by exit code, and creep's own
# Markdown report, which escapes every string from the scanned repository or
# the model into code spans (internal/report codeSpan); nothing else from
# the report or the event reaches the body. The report is cut at a line
# boundary to stay under GitHub's comment limit.
#
# Environment: GH_TOKEN (the workflow token, whose comments are
# github-actions[bot]'s), REPOSITORY, PR_NUMBER, EXIT_CODE, MARKDOWN (empty
# when creep wrote no report), RUNNER_TEMP.
set -euo pipefail

readonly marker="<!-- creep-action:pr-comment -->"
readonly author="github-actions[bot]"
readonly max_report_bytes=60000

fail() {
  echo "::error title=creep::$1"
  exit 1
}

verdict_line() {
  case "$1" in
    0) echo "**Nothing blocking** (exit 0)." ;;
    1) echo "**Gate exceeded** (exit 1): a finding reaches the gate." ;;
    2) echo "**Usage or configuration error** (exit 2): see the job log." ;;
    3) echo "**Model, canary, calibration or sandbox error** (exit 3): see the job log." ;;
    4) echo "**Incomplete run** (exit 4): not everything was evaluated, so this fails like a gate failure." ;;
    *) echo "**Unexpected exit code**: see the job log." ;;
  esac
}

# Prints at most max_report_bytes of the report, dropping the line the cut
# lands in: every code span creep writes sits on one line, so no span or
# multi-byte rune is left open.
report_excerpt() {
  local size
  size="$(wc -c <"$1")"
  if [ "$size" -le "$max_report_bytes" ]; then
    cat "$1"
    return 0
  fi
  head -c "$max_report_bytes" "$1" | sed '$d'
  printf '\n_Report cut to fit a comment; the full report is in code scanning and in .creep/report.md._\n'
}

write_body() {
  {
    echo "$marker"
    echo "### creep"
    echo
    verdict_line "$EXIT_CODE"
    echo
    if [ -n "${MARKDOWN:-}" ]; then
      report_excerpt "$MARKDOWN"
    else
      echo "_creep wrote no report for this run._"
    fi
  } >"$1"
}

[[ "${PR_NUMBER:-}" =~ ^[1-9][0-9]{0,9}$ ]] || fail "no pull request number"
[[ "${REPOSITORY:-}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail "no repository name"
[[ "${EXIT_CODE:-}" =~ ^[0-9]{1,3}$ ]] || fail "no creep exit code"
if [ -n "${MARKDOWN:-}" ] && { [ ! -f "$MARKDOWN" ] || [ -L "$MARKDOWN" ]; }; then
  fail "the Markdown report is not a regular file"
fi

body="$(mktemp "${RUNNER_TEMP:?}/creep-comment.XXXXXX")"
write_body "$body"
ids="$(gh api --paginate "repos/$REPOSITORY/issues/$PR_NUMBER/comments" \
  --jq ".[] | select(.user.login == \"$author\" and (.body | startswith(\"$marker\"))) | .id")"
id="${ids%%$'\n'*}"
if [ -z "$id" ]; then
  gh api --method POST "repos/$REPOSITORY/issues/$PR_NUMBER/comments" -F "body=@$body" >/dev/null
  echo "creep: pull request comment posted"
  exit 0
fi
[[ "$id" =~ ^[0-9]{1,20}$ ]] || fail "unexpected comment id"
gh api --method PATCH "repos/$REPOSITORY/issues/comments/$id" -F "body=@$body" >/dev/null
echo "creep: pull request comment updated"

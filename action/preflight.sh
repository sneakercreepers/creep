#!/usr/bin/env bash
# Event and fork policy of the creep Action (ADR 0023). Runs before anything
# is downloaded. Only listed events run: every other one (pull_request_target,
# workflow_run, issue_comment, ...) can run a fork's
# code with the base repository's secrets. A pull request from a fork must
# carry no secret. Writes fork=true|false to $GITHUB_OUTPUT.
#
# Environment: EVENT_NAME, REPOSITORY, HEAD_REPO (the pull request's head
# repository, empty otherwise), INPUT_API_KEY and the secret variables below.
set -euo pipefail

# Keys a model client reads. A backstop: the Action cannot see every secret
# a workflow holds, only the ones it would hand to creep or a model CLI.
secret_vars=(CREEP_API_KEY ANTHROPIC_API_KEY CLAUDE_CODE_OAUTH_TOKEN OPENAI_API_KEY GEMINI_API_KEY GOOGLE_API_KEY)

has_secret() {
  [ -n "${INPUT_API_KEY:-}" ] && return 0
  local name
  for name in "${secret_vars[@]}"; do
    [ -n "${!name:-}" ] && return 0
  done
  return 1
}

# A name that is not plain lower case is not echoed into a workflow command.
printable_event() {
  if [[ "${EVENT_NAME:-}" =~ ^[a-z_]{1,64}$ ]]; then
    printf '%s' "$EVENT_NAME"
  else
    printf '(unprintable)'
  fi
}

case "${EVENT_NAME:-}" in
  push | schedule | workflow_dispatch | merge_group)
    echo "fork=false" >>"$GITHUB_OUTPUT"
    exit 0
    ;;
  pull_request) ;;
  *)
    echo "::error title=creep::event $(printable_event) is not supported: run the Action on pull_request, push, schedule, workflow_dispatch or merge_group. Other events can run a fork's code with this repository's secrets."
    exit 1
    ;;
esac

if [ -n "${HEAD_REPO:-}" ] && [ "$HEAD_REPO" = "${REPOSITORY:-}" ]; then
  echo "fork=false" >>"$GITHUB_OUTPUT"
  exit 0
fi

if has_secret; then
  echo "::error title=creep::refusing to run: this pull request comes from a fork and a model key is set. Never pass secrets to a fork's code; scan it after review on push, or in a maintainer-run workflow."
  exit 1
fi
echo "::notice title=creep::pull request from a fork: no secret is passed, and the pull request comment is skipped (the token is read-only)."
echo "fork=true" >>"$GITHUB_OUTPUT"

#!/usr/bin/env bash
# Downloads the newest nightly bench results from main into $2 (#36), for
# the release workflow's regression gate. It takes the newest completed run
# of bench.yml on main that still holds a bench-local artifact, whatever its
# conclusion: a run the gate failed still uploads its results, and the gate
# runs on them again. Artifacts last 14 days, so no run in that window, or a
# failed read, fails the release: run the Bench workflow, then tag again.
# Only schedule and workflow_dispatch runs of this repository count: a pull
# request run, a fork's branch named main included, never feeds the gate.
# Needs GH_TOKEN with actions: read.
set -euo pipefail

repo="${1:?usage: bench-latest.sh <owner/repo> <dir>}"
dir="${2:?usage: bench-latest.sh <owner/repo> <dir>}"

runs="$(gh api "repos/$repo/actions/workflows/bench.yml/runs?branch=main&status=completed&per_page=30" \
  --jq '.workflow_runs[] | "\(.id) \(.event) \(.head_repository.full_name) \(.head_sha) \(.created_at)"')"
while read -r id event head sha created; do
  [ -n "$id" ] || continue
  case "$event" in schedule | workflow_dispatch) ;; *) continue ;; esac
  [ "$head" = "$repo" ] || continue
  n="$(gh api "repos/$repo/actions/runs/$id/artifacts" \
    --jq '[.artifacts[] | select(.name == "bench-local" and .expired == false)] | length')"
  [ "$n" = 1 ] || continue
  gh run download "$id" --repo "$repo" --name bench-local --dir "$dir"
  echo "bench results from run $id (commit $sha, $created)"
  exit 0
done <<<"$runs"

echo "::error::no bench-local results on main in the last 14 days; run the Bench workflow before releasing" >&2
exit 1

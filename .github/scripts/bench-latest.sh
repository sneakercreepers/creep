#!/usr/bin/env bash
# Downloads the newest nightly bench results from main into $2 (#36), for
# the release workflow's regression gate. It takes the newest completed run
# of bench.yml on main that holds a bench-local artifact. The bench uploads
# it only when it finished (exit 0 or 4), so a night whose model, Ollama or
# runner failed falls back to the last run that measured something; a run
# whose gate failed keeps its results, and the gate fails on them again, so
# a regression blocks until a newer run measures better. Artifacts last 14
# days: no run in that window, or a failed read, fails the release. To
# recover, dispatch the Bench workflow (model: local) on main, then re-run
# the release.
# Only schedule and workflow_dispatch runs of this repository count: a pull
# request run, a fork's branch named main included, never feeds the gate.
# Needs GH_TOKEN with actions: read.
set -euo pipefail

repo="${1:?usage: bench-latest.sh <owner/repo> <dir>}"
dir="${2:?usage: bench-latest.sh <owner/repo> <dir>}"

# Asked per event, so pull request runs cannot push the nightly ones out of
# the page; 30 of each covers the 14 days artifacts last. Newest first.
since="$(date -u -d '15 days ago' +%Y-%m-%d)"
runs="$(for event in schedule workflow_dispatch; do
  gh api "repos/$repo/actions/workflows/bench.yml/runs?branch=main&status=completed&event=$event&created=%3E%3D$since&per_page=30" \
    --jq '.workflow_runs[] | "\(.created_at) \(.id) \(.event) \(.head_repository.full_name) \(.head_sha)"'
done | sort -r)"
while read -r created id event head sha; do
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

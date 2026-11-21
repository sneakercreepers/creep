#!/usr/bin/env bash
# Reports every difference between .github/rulesets, .github/settings and the
# live repository, without changing anything (#50). Exit 0: no drift; 1: drift;
# 2: a setting could not be read, so the check never passes on a failed fetch.
# Needs gh authenticated as a repository admin: GitHub returns bypass actors
# and environment protections only to admins, so another reader would hide drift.
# Not part of make check: CI has no admin token for these reads.
set -uo pipefail

repo="${1:?usage: settings-drift.sh <owner/repo>}"
tmp="$(mktemp -d)" || exit 2
tool="$tmp/settingsdrift$(go env GOEXE)"
live="$tmp/live.json"
trap 'rm -f "$tool" "$live" "$tmp/rulesets.txt"; rmdir "$tmp"' EXIT
drift=0

fail() { echo "settings-drift: $*" >&2; exit 2; }

# fetch ENDPOINT [JQ] writes the live JSON, reshaped by JQ when given.
fetch() {
  if [ $# -gt 1 ]; then
    gh api "repos/$repo/$1" --jq "$2" >"$live" || fail "cannot read $1"
  else
    gh api "repos/$repo/$1" >"$live" || fail "cannot read $1"
  fi
}

# compare LABEL FILE compares FILE with the last fetch.
compare() {
  "$tool" "$1" "$2" "$live"
  case $? in
    0) ;;
    1) drift=1 ;;
    *) exit 2 ;;
  esac
}

report() { echo "drift $*"; drift=1; }

[ "$(gh api "repos/$repo" --jq .permissions.admin)" = true ] || fail "gh must be authenticated as an admin of $repo"
go build -o "$tool" ./internal/tools/settingsdrift || fail "cannot build internal/tools/settingsdrift"

gh api --paginate "repos/$repo/rulesets" --jq '.[] | "\(.id) \(.name)"' >"$tmp/rulesets.txt" || fail "cannot list rulesets"
for f in .github/rulesets/*.json; do
  name="$(basename "$f" .json)"
  id="$(awk -v n="$name" '{ id = $1; sub(/^[^ ]* /, ""); if ($0 == n) print id }' "$tmp/rulesets.txt")"
  case "$id" in
    "") report "ruleset $name: not on GitHub" ;;
    *[!0-9]*) fail "ruleset $name: more than one live ruleset has this name" ;;
    *) fetch "rulesets/$id"; compare "ruleset $name" "$f" ;;
  esac
done
while read -r id name; do
  [ -f ".github/rulesets/$name.json" ] || report "ruleset $id: live only, not in .github/rulesets"
done <"$tmp/rulesets.txt"

fetch actions/permissions
compare "actions permissions" .github/settings/actions-permissions.json
# A failed read must exit 2, not pass as "not selected" drift.
allowed="$(gh api "repos/$repo/actions/permissions" --jq .allowed_actions)" || fail "cannot read actions/permissions"
if [ "$allowed" = selected ]; then
  fetch actions/permissions/selected-actions
  compare "allowed actions" .github/settings/actions-selected.json
else
  report "allowed actions: not in effect until allowed_actions is selected"
fi
fetch actions/permissions/workflow
compare "workflow permissions" .github/settings/workflow-permissions.json
fetch immutable-releases
compare "immutable releases" .github/settings/immutable-releases.json

# The environment reads back in another shape than it is written; reshape it
# to the file's keys. A reviewer added or removed live is drift.
fetch environments/release '{
  prevent_self_review: ([.protection_rules[]? | select(.type == "required_reviewers") | .prevent_self_review] | first // false),
  can_admins_bypass,
  reviewers: [.protection_rules[]? | select(.type == "required_reviewers") | .reviewers[] | {type, id: .reviewer.id}],
  deployment_branch_policy
}'
compare "environment release" .github/settings/release-environment.json
policies="$(gh api --paginate "repos/$repo/environments/release/deployment-branch-policies" \
  --jq '.branch_policies[] | select(.name != "v*" or .type != "tag") | "\(.type) \(.name)"')" || fail "cannot read release deployment policies"
[ -z "$policies" ] || report "environment release: deployment policies other than the v* tag: $(printf '%s' "$policies" | LC_ALL=C tr -c '[:graph:]' ' ')"
n="$(gh api "repos/$repo/environments/release/deployment-branch-policies" \
  --jq '[.branch_policies[] | select(.name == "v*" and .type == "tag")] | length')" || fail "cannot read release deployment policies"
[ "$n" != 0 ] || report "environment release: no v* tag deployment policy"

[ "$drift" = 0 ] && echo "no drift"
exit "$drift"

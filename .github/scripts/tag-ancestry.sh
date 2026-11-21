#!/usr/bin/env bash
# Refuses to release a commit that is not on main.
# Rulesets cannot tie a v* tag to a branch, so this is the only check (#19).
# Only main is accepted: it is the one branch a ruleset makes PR-only with
# required checks; release/* is only admin-written (#50). Accept a release/*
# branch only once a ruleset in .github/rulesets protects it the same way
# (v0.1 release pentest P6).
# Needs a full fetch (actions/checkout fetch-depth: 0) for origin/main.
set -euo pipefail

commit="${1:?usage: tag-ancestry.sh <commit>}"

# An unknown commit makes merge-base fail, which counts as not an ancestor.
if git merge-base --is-ancestor "$commit" refs/remotes/origin/main 2>/dev/null; then
  echo "$commit is on main"
  exit 0
fi

echo "::error::$commit is not on main; refusing to release" >&2
exit 1

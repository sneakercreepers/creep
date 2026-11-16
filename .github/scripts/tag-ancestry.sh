#!/usr/bin/env bash
# Refuses to release a commit that is on neither main nor a release/* branch.
# Rulesets cannot tie a v* tag to a branch, so this is the only check (#19).
# Needs a full fetch (actions/checkout fetch-depth: 0) for the origin/* refs.
set -euo pipefail

commit="${1:?usage: tag-ancestry.sh <commit>}"
branches="refs/remotes/origin/main $(git for-each-ref --format='%(refname)' 'refs/remotes/origin/release/*')"

for branch in $branches; do
  # An unknown commit makes merge-base fail, which counts as not an ancestor.
  if git merge-base --is-ancestor "$commit" "$branch" 2>/dev/null; then
    echo "$commit is on ${branch#refs/remotes/origin/}"
    exit 0
  fi
done

echo "::error::$commit is on neither main nor a release/* branch; refusing to release" >&2
exit 1

#!/usr/bin/env bash
# Pushes the Homebrew cask and the Scoop manifest that goreleaser wrote into
# dist/ to sneakercreepers/homebrew-tap and sneakercreepers/scoop-bucket
# (#344, ADR 0033). The release job runs it only after the release is
# verified and public, so a manifest never names a draft or unverified asset.
# Without PACKAGE_REPOS_TOKEN, or for a prerelease tag, it publishes nothing
# and says why, and the release still succeeds.
#
# Usage: package-repos.sh <tag> <dist dir>
set -euo pipefail

tag="$1"
dist="$2"

if [ -z "${PACKAGE_REPOS_TOKEN:-}" ]; then
  echo "::warning::PACKAGE_REPOS_TOKEN is not set in the release environment; the Homebrew tap and Scoop bucket were not updated for $tag"
  exit 0
fi
if [[ "$tag" == *-* ]]; then
  echo "::notice::$tag is a prerelease; the Homebrew tap and Scoop bucket keep the last release"
  exit 0
fi
export GH_TOKEN="$PACKAGE_REPOS_TOKEN"

publish() { # repo path file
  local sha args
  test -s "$3" || { echo "::error::$3 was not generated"; exit 1; }
  # A missing file has no sha yet; any other read error fails the PUT below.
  sha="$(gh api "repos/$1/contents/$2?ref=main" --jq .sha 2>/dev/null || true)"
  args=(-X PUT "repos/$1/contents/$2"
    -f "message=creep $tag"
    -f "content=$(base64 -w0 "$3")"
    -f branch=main
    -f "committer[name]=creep-release"
    -f "committer[email]=noreply@github.com")
  if [ -n "$sha" ]; then
    args+=(-f "sha=$sha")
  fi
  gh api "${args[@]}" --jq .commit.html_url
}

publish sneakercreepers/homebrew-tap Casks/creep.rb "$dist/homebrew/Casks/creep.rb"
publish sneakercreepers/scoop-bucket bucket/creep.json "$dist/scoop/creep.json"

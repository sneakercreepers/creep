#!/usr/bin/env bash
# Pushes the Homebrew cask and the Scoop manifest that goreleaser wrote into
# dist/ to sneakercreepers/homebrew-tap and sneakercreepers/scoop-bucket
# (#344, ADR 0033). The release workflow's package-repos job runs it on a
# fresh runner, after the release is public and the job has checked
# checksums.txt's cosign signature, so a manifest never names a draft or
# unverified asset. Without PACKAGE_REPOS_TOKEN, or for a prerelease tag, it
# publishes nothing and says why, and the release still succeeds. It never
# moves the tap or bucket back to an older version; a rerun after a partial
# publish skips the file that already holds this release.
#
# Usage: package-repos.sh <tag> <dist dir>
#        package-repos.sh --check-pins <tag> <version> <dist dir>
# The second form only checks the pins, for the snapshot in the PR dry-run,
# whose version is not its tag.
set -euo pipefail
shopt -s inherit_errexit

downloads=https://github.com/sneakercreepers/creep/releases/download
tap=sneakercreepers/homebrew-tap
bucket=sneakercreepers/scoop-bucket

fail() { echo "::error::$*" >&2; exit 1; }

# file_version prints the first `version` value of a cask or a manifest.
file_version() { # file
  grep -m1 -oE '^\s*("version":|version)\s+"[^"]+"' "$1" | sed -E 's/.*"([^"]+)"$/\1/' || true
}

# pin_pairs prints "<sha256> <url>" for each archive a cask or manifest pins,
# in file order. The cask writes sha256 before url and the manifest url before
# hash, but each block holds one of each, so the nth sum belongs to the nth url.
pin_pairs() { # file version
  local url
  paste -d' ' \
    <(grep -oE '^\s*(sha256|"hash":)\s+"[^"]*"' "$1" | sed -E 's/.*"([^"]*)"$/\1/') \
    <(grep -oE '^\s*(url|"url":)\s+"[^"]*"' "$1" | sed -E 's/.*"([^"]*)"$/\1/') |
    while read -r sum url; do echo "$sum ${url//'#{version}'/$2}"; done
}

# check_pins fails unless file is at version and pins, at release URLs of tag,
# exactly the archives checksums.txt lists for its platforms, each by its sum.
check_pins() { # file tag version archive-regex
  local want got=() sum url
  test -s "$1" || fail "$1 was not generated"
  test "$(file_version "$1")" = "$3" || fail "$1 is not at version $3"
  want="$(grep -E "^[0-9a-f]{64}  creep_${3//./\\.}_$4\$" "$dist/checksums.txt" | sort || true)"
  test -n "$want" || fail "checksums.txt lists no archive for $1"
  while read -r sum url; do
    [[ "$sum" =~ ^[0-9a-f]{64}$ ]] || fail "$1 has a url without a sha256"
    [[ "$url" == "$downloads/$2/"* ]] || fail "$1 names $url, not an asset of release $2"
    got+=("$sum  ${url##*/}")
  done < <(pin_pairs "$1" "$3")
  test "$(printf '%s\n' "${got[@]}" | sort)" = "$want" ||
    fail "$1 does not pin exactly the archives checksums.txt lists, by their sha256"
}

check_all_pins() { # tag version
  check_pins "$dist/homebrew/Casks/creep.rb" "$1" "$2" '(darwin|linux)_[a-z0-9]+\.tar\.gz'
  check_pins "$dist/scoop/creep.json" "$1" "$2" 'windows_[a-z0-9]+\.zip'
}

# remote_state prints "new" when repo has no file at path, "same" when it
# already holds this file, or "update <sha>" when it holds an older version.
# A read error counts as missing: the PUT without a sha then fails on an
# existing file, so the guard below cannot be skipped by a failed read. The
# exit status decides, not the output: on a 404 gh still prints the error
# body on stdout.
remote_state() { # repo path file
  local sha remote old new
  if ! sha="$(gh api "repos/$1/contents/$2?ref=main" --jq .sha 2>/dev/null)" || [ -z "$sha" ]; then
    echo new
    return
  fi
  remote="$(mktemp)"
  gh api -H 'Accept: application/vnd.github.raw' "repos/$1/contents/$2?ref=main" >"$remote"
  if cmp -s "$remote" "$3"; then echo same; return; fi
  old="$(file_version "$remote")"
  new="$(file_version "$3")"
  test -n "$old" || fail "$1 $2 has no version; refusing to overwrite it"
  test "$old" != "$new" || fail "$1 $2 already holds $new with other content"
  test "$(printf '%s\n%s\n' "$old" "$new" | sort -V | tail -n1)" = "$new" ||
    fail "$1 $2 holds $old, newer than $new; refusing a downgrade"
  echo "update $sha"
}

publish() { # repo path file state
  local args
  if [ "$4" = same ]; then
    echo "::notice::$1 $2 already holds $tag"
    return
  fi
  args=(-X PUT "repos/$1/contents/$2"
    -f "message=creep $tag"
    -f "content=$(base64 -w0 "$3")"
    -f branch=main
    -f "committer[name]=creep-release"
    -f "committer[email]=noreply@github.com")
  if [ "$4" != new ]; then
    args+=(-f "sha=${4#update }")
  fi
  gh api "${args[@]}" --jq .commit.html_url
}

if [ "${1:-}" = --check-pins ]; then
  dist="$4"
  check_all_pins "$2" "$3"
  echo "the cask and the manifest pin the archives checksums.txt lists"
  exit 0
fi

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
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "$tag is not a release tag"
check_all_pins "$tag" "${tag#v}"

export GH_TOKEN="$PACKAGE_REPOS_TOKEN"
# Both files are checked before either is pushed, so a refused downgrade
# leaves the tap and the bucket as they were.
tap_state="$(remote_state "$tap" Casks/creep.rb "$dist/homebrew/Casks/creep.rb")"
bucket_state="$(remote_state "$bucket" bucket/creep.json "$dist/scoop/creep.json")"
publish "$tap" Casks/creep.rb "$dist/homebrew/Casks/creep.rb" "$tap_state"
publish "$bucket" bucket/creep.json "$dist/scoop/creep.json" "$bucket_state"

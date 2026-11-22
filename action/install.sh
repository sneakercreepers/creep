#!/usr/bin/env bash
# Installs a creep release for the runner and verifies it before use
# (ADR 0023): the archive's SHA-256 must match checksums.txt, and its build
# provenance must be a Sigstore-signed attestation from this repository's
# release workflow at the release tag, built on a GitHub-hosted runner. Any
# mismatch stops the Action. Writes path=<binary> to $GITHUB_OUTPUT.
#
# Environment: CREEP_PATH (self-test only), INPUT_VERSION, ACTION_REF,
# GH_TOKEN, RUNNER_OS, RUNNER_ARCH, RUNNER_TEMP.
set -euo pipefail

readonly repo="sneakercreepers/creep"
readonly signer="$repo/.github/workflows/release.yml"
readonly tag_pattern='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'

fail() {
  echo "::error title=creep::$1"
  exit 1
}

# Sets tag: the version input, else the tag the Action is used at. A commit
# SHA or a branch names no release, so it needs the input.
set_tag() {
  tag="${INPUT_VERSION:-${ACTION_REF:-}}"
  if [[ ! "$tag" =~ $tag_pattern ]]; then
    fail "set the version input to a creep release tag (vX.Y.Z): the Action ref is not one, so it names no release to verify"
  fi
}

# Sets target: the release's os_arch for this runner.
set_target() {
  local os arch
  case "${RUNNER_OS:-}" in
    Linux) os=linux ;;
    macOS) os=darwin ;;
    *) fail "the Action runs on Linux and macOS runners only" ;;
  esac
  case "${RUNNER_ARCH:-}" in
    X64) arch=amd64 ;;
    ARM64) arch=arm64 ;;
    *) fail "the Action runs on X64 and ARM64 runners only" ;;
  esac
  target="${os}_${arch}"
}

sha256_of() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# Exactly one checksums.txt line must name the archive, with 64 hex digits.
check_checksum() {
  local dir="$1" archive="$2" want got
  want="$(awk -v f="$archive" '$2 == f { print $1 }' "$dir/checksums.txt")"
  [[ "$want" =~ ^[0-9a-f]{64}$ ]] || fail "checksums.txt has no single SHA-256 for $archive"
  got="$(sha256_of "$dir/$archive")" || fail "could not hash $archive"
  [ "$got" = "$want" ] || fail "checksum mismatch for $archive: do not use this release"
}

if [ -n "${CREEP_PATH:-}" ]; then
  [ -f "$CREEP_PATH" ] && [ -x "$CREEP_PATH" ] || fail "creep-path is not an executable file"
  echo "::warning title=creep::creep-path is set: running an unverified local binary. It exists for the Action's own self-test; never set it in a real workflow."
  echo "path=$CREEP_PATH" >>"$GITHUB_OUTPUT"
  exit 0
fi

set_tag
set_target
archive="creep_${tag#v}_${target}.tar.gz"
dir="$(mktemp -d "${RUNNER_TEMP:?}/creep-install.XXXXXX")"

gh release download "$tag" --repo "$repo" --pattern "$archive" --pattern checksums.txt --dir "$dir" ||
  fail "could not download $archive and checksums.txt from release $tag"
check_checksum "$dir" "$archive"
gh attestation verify "$dir/$archive" --repo "$repo" --signer-workflow "$signer" \
  --source-ref "refs/tags/$tag" --deny-self-hosted-runners >/dev/null ||
  fail "build provenance of $archive did not verify: do not use this release"

mkdir "$dir/bin"
tar -xzf "$dir/$archive" -C "$dir/bin" creep || fail "could not extract creep from $archive"
[ -f "$dir/bin/creep" ] && [ ! -L "$dir/bin/creep" ] || fail "$archive holds no creep binary"
echo "creep $tag ($target): checksum and build provenance verified"
echo "path=$dir/bin/creep" >>"$GITHUB_OUTPUT"

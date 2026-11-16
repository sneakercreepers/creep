#!/usr/bin/env bash
# Installs goreleaser and syft for the release workflow into /usr/local/bin,
# each checked against a pinned sha256 of its linux x86_64 archive. Each
# sha256 matches both the release checksums file and the GitHub asset digest.
set -euo pipefail

GORELEASER_VERSION=2.20.2
GORELEASER_SHA256=f3d24969a7389a46613875711d15a96d8f6ef1553d84c6ace09d69ac1e7d44c0
SYFT_VERSION=1.57.1
SYFT_SHA256=bf52519eb57f675d47c07d43213cb6dff6449f3d6d1147ff6701ed91f44eef0c

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

install_tool() { # url sha256 binary
  archive="$work/$(basename "$1")"
  curl -fsSL -o "$archive" "$1"
  echo "$2  $archive" | sha256sum -c -
  tar -xzf "$archive" -C "$work" "$3"
  sudo install -m 0755 "$work/$3" "/usr/local/bin/$3"
}

install_tool "https://github.com/goreleaser/goreleaser/releases/download/v${GORELEASER_VERSION}/goreleaser_Linux_x86_64.tar.gz" "$GORELEASER_SHA256" goreleaser
install_tool "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" "$SYFT_SHA256" syft

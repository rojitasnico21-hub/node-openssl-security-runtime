#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
umask 022

[[ $# -eq 3 ]] || { echo "usage: $0 <amd64|arm64> <manifest> <destination-dir>" >&2; exit 64; }
arch="$1"
manifest="$2"
destination="$3"
script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$arch" in
  amd64) asset=Linux-64bit ;;
  arm64) asset=Linux-ARM64 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 64 ;;
esac
read_manifest() {
  node "$script_root/scripts/read-manifest-value.mjs" "$manifest" "$1"
}
version="$(read_manifest toolchain.trivy.version)"
expected="$(read_manifest "toolchain.trivy.${arch}Sha256")"
archive="trivy_${version}_${asset}.tar.gz"
tmp="$(mktemp)"
unpack="$(mktemp -d)"
trap 'rm -rf "$tmp" "$unpack"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 --retry 2 --output "$tmp" "https://github.com/aquasecurity/trivy/releases/download/v${version}/${archive}"
printf '%s  %s\n' "$expected" "$tmp" | sha256sum -c -
tar -xzf "$tmp" -C "$unpack" trivy
install -d -m 0755 "$destination"
install -m 0755 "$unpack/trivy" "$destination/trivy"
"$destination/trivy" --version | grep -F "Version: ${version}"

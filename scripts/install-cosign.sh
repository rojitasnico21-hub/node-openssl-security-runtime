#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
umask 022

[[ $# -eq 3 ]] || { echo "usage: $0 <amd64|arm64> <manifest> <destination-dir>" >&2; exit 64; }
arch="$1"; manifest="$2"; destination="$3"
script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$arch" in amd64) asset=amd64 ;; arm64) asset=arm64 ;; *) exit 64 ;; esac
read_manifest() {
  node "$script_root/scripts/read-manifest-value.mjs" "$manifest" "$1"
}
version="$(read_manifest toolchain.cosign.version)"
checksums_expected="$(read_manifest toolchain.cosign.checksumsSha256)"
binary_expected="$(read_manifest toolchain.cosign.${arch}Sha256)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 --retry 2 --output "$work/checksums.txt" "https://github.com/sigstore/cosign/releases/download/v${version}/cosign_checksums.txt"
printf '%s  %s\n' "$checksums_expected" "$work/checksums.txt" | sha256sum -c -
curl --fail --location --proto '=https' --tlsv1.2 --retry 2 --output "$work/cosign" "https://github.com/sigstore/cosign/releases/download/v${version}/cosign-linux-${asset}"
printf '%s  %s\n' "$binary_expected" "$work/cosign" | sha256sum -c -
grep -F "$binary_expected  cosign-linux-${asset}" "$work/checksums.txt"
install -d -m 0755 "$destination"
install -m 0755 "$work/cosign" "$destination/cosign"
"$destination/cosign" version | grep -F "GitVersion:    v${version}"

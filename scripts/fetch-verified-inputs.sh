#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
umask 022

[[ $# -eq 2 ]] || { echo "usage: $0 <BUILD_MANIFEST.json> <output-dir>" >&2; exit 64; }
manifest="$1"
out="$2"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for tool in curl sha256sum cmp node mkdir; do command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }; done
mkdir -p "$out"

read_manifest() {
  node "$repo_root/scripts/read-manifest-value.mjs" "$manifest" "$1"
}
fetch() {
  local name="$1" url="$2" expected="$3"
  curl --fail --location --proto '=https' --tlsv1.2 --retry 2 --output "$out/$name" "$url"
  printf '%s  %s\n' "$expected" "$out/$name" | sha256sum -c -
}

fetch node.tar.xz "$(read_manifest node.sourceUrl)" "$(read_manifest node.sourceSha256)"
fetch openssl.tar.gz "$(read_manifest openssl.sourceUrl)" "$(read_manifest openssl.sourceSha256)"
fetch official.patch "$(read_manifest openssl.officialPatchUrl)" "$(read_manifest openssl.officialPatchSha256)"
fetch libtext-template-perl_1.61-1_all.deb "$(read_manifest dependencies.textTemplate.url)" "$(read_manifest dependencies.textTemplate.sha256)"

if ! cmp -s "$out/official.patch" "$repo_root/patches/openssl-CVE-2026-14456-official.patch"; then
  echo "repository official patch differs from the verified upstream patch" >&2
  exit 1
fi
printf 'OFFICIAL_PATCH_SOURCE=VERIFIED\n'

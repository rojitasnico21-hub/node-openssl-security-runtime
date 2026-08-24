#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

[[ $# -eq 2 ]] || { echo "usage: $0 <amd64|arm64> <image-ref>" >&2; exit 64; }
arch="$1"; image="$2"
case "$arch" in
  amd64) expected_process=x64; expected_machine='Advanced Micro Devices X86-64' ;;
  arm64) expected_process=arm64; expected_machine=AArch64 ;;
  *) exit 64 ;;
esac
container="$(docker create "$image" --version)"
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT
root="$(mktemp -d)"
trap 'rm -rf "$root"; docker rm -f "$container" >/dev/null 2>&1 || true' EXIT
docker export "$container" | tar -C "$root" -xf -
[[ -x "$root/nodejs/bin/node" ]]
[[ "$(find "$root" -type f -name node | wc -l | tr -d ' ')" = 1 ]]
if find "$root" -type f \( -name 'libssl.so*' -o -name 'libcrypto.so*' \) -print -quit | grep -q .; then
  echo 'final runtime OCI contains external libssl/libcrypto' >&2
  exit 1
fi
readelf -h "$root/nodejs/bin/node" | grep -Fq "Machine:                           $expected_machine"
"$root/nodejs/bin/node" -p "process.arch === '$expected_process' ? 'ARCH_OK' : process.arch" | grep -Fx ARCH_OK
printf 'FINAL_RUNTIME_IMAGE=%s\n' PASS

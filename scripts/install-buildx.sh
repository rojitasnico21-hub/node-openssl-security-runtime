#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
umask 022

[[ $# -eq 3 ]] || { echo "usage: $0 <amd64|arm64> <manifest> <docker-config-dir>" >&2; exit 64; }
arch="$1"
manifest="$2"
docker_config="$3"
case "$arch" in
  amd64) asset_arch=amd64 ;;
  arm64) asset_arch=arm64 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 64 ;;
esac

read_manifest() {
  node -e 'const m=require(process.argv[1]); const key=process.argv[2].split("."); let v=m; for(const k of key)v=v[k]; if(typeof v!=="string"||!v)process.exit(1); process.stdout.write(v)' "$manifest" "$1"
}
version="$(read_manifest toolchain.buildx.version)"
expected="$(read_manifest "toolchain.buildx.${arch}Sha256")"
url="https://github.com/docker/buildx/releases/download/${version}/buildx-${version}.linux-${asset_arch}"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 --retry 2 --output "$tmp" "$url"
printf '%s  %s\n' "$expected" "$tmp" | sha256sum -c -
install -d -m 0755 "$docker_config/cli-plugins"
install -m 0755 "$tmp" "$docker_config/cli-plugins/docker-buildx"
DOCKER_CONFIG="$docker_config" docker buildx version | grep -F "$version"

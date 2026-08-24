#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
umask 022

[[ $# -eq 4 ]] || { echo "usage: $0 <amd64|arm64> <manifest> <docker-config-dir> <builder-name>" >&2; exit 64; }
arch="$1"
manifest="$2"
docker_config="$3"
builder="$4"
script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
buildkit="$(node "$script_root/scripts/read-manifest-value.mjs" "$manifest" toolchain.buildkitImage)"
[[ "$buildkit" == *"@sha256:"* ]] || { echo "BuildKit image is not digest pinned" >&2; exit 1; }
DOCKER_CONFIG="$docker_config" docker buildx create --name "$builder" --driver docker-container --driver-opt "image=$buildkit" --use
DOCKER_CONFIG="$docker_config" docker buildx inspect --bootstrap
DOCKER_CONFIG="$docker_config" docker buildx ls | grep -F "$builder"
printf 'BUILDKIT_IMAGE=%s\n' "$buildkit"
printf 'BUILDER_ARCH=%s\n' "$arch"

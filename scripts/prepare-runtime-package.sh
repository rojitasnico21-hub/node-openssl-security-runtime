#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
umask 022

[[ $# -eq 3 ]] || { echo "usage: $0 <runtime-dir> <source-date-epoch> <output-dir>" >&2; exit 64; }
runtime_dir="$1"
epoch="$2"
output_dir="$3"
for tool in tar gzip sha256sum find sort xargs grep mktemp; do command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }; done
[[ "$epoch" =~ ^[0-9]+$ ]] || { echo "SOURCE_DATE_EPOCH must be an integer" >&2; exit 1; }

required=(
  nodejs/bin/node evidence/RUNTIME_PROVENANCE.json evidence/ELF.json evidence/DT_NEEDED.txt
  evidence/PATCH_EQUIVALENCE.json evidence/GENERATED_HEADERS.json
  evidence/CVE_NEGATIVE_CONTROL.json evidence/CVE_POSITIVE_CONTROL.json
  evidence/TRIVY.json evidence/TRIVY_DB.json evidence/SBOM.cdx.json
  licenses/LICENSE licenses/Node-LICENSE licenses/OpenSSL-LICENSE.txt licenses/MODIFICATION-NOTICE.md
)
for path in "${required[@]}"; do [[ -f "$runtime_dir/$path" ]] || { echo "missing runtime package input: $path" >&2; exit 1; }; done
[[ -x "$runtime_dir/nodejs/bin/node" ]] || { echo "Node executable mode is missing" >&2; exit 1; }

(
  cd "$runtime_dir"
  find nodejs closure evidence licenses -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
)
if grep -Eq '(^|[[:space:]])(/|.*(/tmp|/home/runner|RUNNER_TEMP))' "$runtime_dir/SHA256SUMS"; then
  echo "checksum manifest contains an absolute or transient path" >&2
  exit 1
fi
mkdir -p "$output_dir"
package="$output_dir/node-openssl-security-runtime.tar.gz"
(
  cd "$runtime_dir"
  tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    --pax-option=delete=atime,delete=ctime -cf - nodejs closure evidence licenses SHA256SUMS \
    | gzip -n > "$package"
)
(
  cd "$output_dir"
  sha256sum "$(basename "$package")" > "$(basename "$package").sha256"
)
verify_dir="$(mktemp -d)"
trap 'rm -rf "$verify_dir"' EXIT
tar -xzf "$package" -C "$verify_dir"
(
  cd "$verify_dir"
  sha256sum -c SHA256SUMS
)
[[ -x "$verify_dir/nodejs/bin/node" ]] || { echo "package extraction lost executable mode" >&2; exit 1; }
tar -tzf "$package" | grep -Eq '(^/|\.\./)' && { echo "package contains unsafe path" >&2; exit 1; } || true
printf 'RUNTIME_PACKAGE_SHA256=%s\n' "$(awk '{print $1}' "$output_dir/$(basename "$package").sha256")"

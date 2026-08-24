#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
umask 022
export LC_ALL=C.UTF-8 TZ=UTC

usage() {
  printf 'usage: %s [--headers-only] <amd64|arm64> <node.tar.xz> <openssl.tar.gz> <official.patch> <adapted.patch> <output-dir>\n' "$0" >&2
  exit 64
}

headers_only=0
if [[ ${1:-} = --headers-only ]]; then
  headers_only=1
  shift
fi
[[ $# -eq 6 ]] || usage

arch="$1"
node_tar="$2"
openssl_tar="$3"
official_patch="$4"
adapted_patch="$5"
output_dir="$6"
script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$script_root/BUILD_MANIFEST.json"
case "$arch" in
  amd64) target_arch=x86_64; openssl_target=linux-x86_64 ;;
  arm64) target_arch=aarch64; openssl_target=linux-aarch64 ;;
  *) usage ;;
esac

for tool in sha256sum tar git make sed grep find install mkdir mktemp cp rm sort xargs awk getconf diff cmp readelf node cc ar; do
  command -v "$tool" >/dev/null || { printf 'missing required tool: %s\n' "$tool" >&2; exit 1; }
done
[[ -f "$manifest" && -f "$official_patch" && -f "$adapted_patch" ]] || { echo "manifest or patch input is absent" >&2; exit 1; }

read_manifest() {
  node "$script_root/scripts/read-manifest-value.mjs" "$manifest" "$1"
}
node_sha="$(read_manifest node.sourceSha256)"
openssl_sha="$(read_manifest openssl.sourceSha256)"
expected_node_version="v$(read_manifest node.version)"
expected_openssl_version="$(read_manifest openssl.basis)"
source_date_epoch="$(node "$script_root/scripts/read-manifest-value.mjs" "$manifest" sourceDateEpoch)"
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || { echo "manifest sourceDateEpoch is invalid" >&2; exit 1; }

printf '%s  %s\n' "$node_sha" "$node_tar" | sha256sum -c -
printf '%s  %s\n' "$openssl_sha" "$openssl_tar" | sha256sum -c -
mkdir -p "$output_dir/evidence" "$output_dir/nodejs/bin" "$output_dir/closure" "$output_dir/licenses"
node "$script_root/scripts/verify-build-manifest.mjs" --out "$output_dir/evidence/PATCH_EQUIVALENCE.json" "$manifest" "$official_patch" "$adapted_patch"

work_root="$(mktemp -d "${TMPDIR:-/tmp}/patched-node.XXXXXX")"
cleanup() { rm -rf "$work_root"; }
trap cleanup EXIT

extract_node() {
  local destination="$1"
  mkdir -p "$destination"
  tar -C "$destination" --strip-components=1 -xJf "$node_tar"
  [[ -d "$destination/deps/openssl/openssl" ]] || { echo "Node source tree is incomplete" >&2; exit 1; }
}
extract_openssl() {
  local destination="$1"
  mkdir -p "$destination"
  tar -C "$destination" --strip-components=1 -xzf "$openssl_tar"
}
apply_adapted_patch() {
  local tree="$1"
  (
    cd "$tree"
    git apply --check --verbose "$adapted_patch"
    git apply --verbose "$adapted_patch"
    ! find . -name '*.rej' -type f -print -quit | grep -q .
  )
}
hash_tree() {
  local tree="$1" destination="$2"
  local temporary
  # Write outside the tree: a manifest inside the tree would hash itself.
  rm -f "$destination"
  temporary="$(mktemp "${TMPDIR:-/tmp}/header-tree.XXXXXX")"
  (
    cd "$tree"
    find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > "$temporary"
  )
  mv "$temporary" "$destination"
}

tree_sha256() {
  local tree="$1"
  (
    cd "$tree"
    find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
  ) | sha256sum | awk '{print $1}'
}

prepare_generation_tree() {
  local patched="$1"
  [[ "$canonical_node" = "$work_root/canonical-node" && "$canonical_full" = "$work_root/canonical-openssl" ]] || {
    echo "refusing to reset a non-canonical generation tree" >&2
    exit 1
  }
  rm -rf "$canonical_node" "$canonical_full"
  extract_node "$canonical_node"
  extract_openssl "$canonical_full"
  if [[ "$patched" = true ]]; then
    apply_adapted_patch "$canonical_node/deps/openssl/openssl"
    apply_adapted_patch "$canonical_full"
  fi
  git init -q "$canonical_node"
  git -C "$canonical_node" add -A
  [[ -n "$(git -C "$canonical_node" ls-files)" ]]
  [[ -z "$(git -C "$canonical_node" ls-files --others --exclude-standard)" ]]
  git -C "$canonical_node" diff --exit-code --quiet
}

record_generation_input_state() {
  local run="$1" patched="$2" output="$3"
  local config_sha openssl_sha vendor_sha indexed_file_count
  config_sha="$(tree_sha256 "$canonical_node/deps/openssl/config")"
  openssl_sha="$(tree_sha256 "$canonical_full")"
  vendor_sha="$(tree_sha256 "$canonical_node/deps/openssl/openssl")"
  indexed_file_count="$(git -C "$canonical_node" ls-files | wc -l | tr -d ' ')"
  node - "$output" "$run" "$patched" "$config_sha" "$openssl_sha" "$vendor_sha" \
    "$source_date_epoch" "$indexed_file_count" <<'NODE'
const { writeFileSync } = require("node:fs");
const [out, run, patched, configSha256, opensslSha256, vendoredOpenSslSha256, sourceDateEpoch, indexedFileCount] = process.argv.slice(2);
writeFileSync(out, `${JSON.stringify({
  schemaVersion: 1,
  run,
  patched: patched === "true",
  indexPopulated: Number(indexedFileCount) > 0,
  indexedFileCount: Number(indexedFileCount),
  untrackedFilesAbsent: true,
  worktreeMatchesIndex: true,
  configTreeSha256: configSha256,
  fullOpenSslTreeSha256: opensslSha256,
  vendoredOpenSslTreeSha256: vendoredOpenSslSha256,
  environment: {
    lcAll: process.env.LC_ALL,
    tz: process.env.TZ,
    path: process.env.PATH,
    sourceDateEpoch,
    umask: "022",
  },
}, null, 2)}\n`);
NODE
}
generate_headers() {
  local node_root="$1" full_openssl="$2" destination="$3" expect_patched="$4"
  local node_openssl="$node_root/deps/openssl/openssl" pruned="$node_root/.openssl-pruned" generated="$node_root/.openssl-generated"
  mv "$node_openssl" "$pruned"
  mv "$full_openssl" "$node_openssl"
  make -C "$node_root/deps/openssl/config" clean
  sed -i 's/#ifdef/%ifdef/g' "$node_openssl/crypto/perlasm/x86asm.pl"
  sed -i 's/#endif/%endif/g' "$node_openssl/crypto/perlasm/x86asm.pl"
  SOURCE_DATE_EPOCH="$source_date_epoch" PATH="/opt/nasm/usr/bin:$PATH" make -C "$node_root/deps/openssl/config"
  grep -Fqx '#include "../../../config/ssl.h"' "$node_openssl/include/openssl/ssl.h"
  if [[ "$expect_patched" = true ]]; then
    for header in \
      "$node_root/deps/openssl/config/archs/linux-x86_64/asm/include/openssl/ssl.h" \
      "$node_root/deps/openssl/config/archs/linux-x86_64/no-asm/include/openssl/ssl.h" \
      "$node_root/deps/openssl/config/archs/linux-aarch64/asm/include/openssl/ssl.h" \
      "$node_root/deps/openssl/config/archs/linux-aarch64/no-asm/include/openssl/ssl.h"; do
      grep -Fqx '#define SSL_VALUE_QUIC_MAX_PENDING_CONNS 16' "$header"
    done
  fi
  mkdir -p "$destination"
  cp -R "$node_root/deps/openssl/config/archs" "$destination/archs"
  cp "$node_openssl/include/openssl/ssl.h" "$destination/ssl.h"
  hash_tree "$destination" "$destination/SHA256SUMS"
  cp "$node_openssl/include/openssl/ssl.h" "$pruned/include/openssl/ssl.h"
  mv "$node_openssl" "$generated"
  mv "$pruned" "$node_openssl"
}

canonical_node="$work_root/canonical-node"
canonical_full="$work_root/canonical-openssl"
input_state_dir="$output_dir/evidence/generated-header-inputs"
mkdir -p "$input_state_dir"

# Every run is independently reconstructed at the same canonical source path.
# This makes absolute paths in OpenSSL configdata.pm an identical input while
# SOURCE_DATE_EPOCH makes OpenSSL buildinf.h deterministic.
prepare_generation_tree false
record_generation_input_state baseline false "$input_state_dir/baseline.json"
generate_headers "$canonical_node" "$canonical_full" "$output_dir/evidence/generated-headers/baseline" false

prepare_generation_tree true
record_generation_input_state patched-run1 true "$input_state_dir/patched-run1.json"
generate_headers "$canonical_node" "$canonical_full" "$output_dir/evidence/generated-headers/patched" true

prepare_generation_tree true
record_generation_input_state patched-run2 true "$input_state_dir/patched-run2.json"
generate_headers "$canonical_node" "$canonical_full" "$output_dir/evidence/generated-headers/repeat" true

prepare_generation_tree true
record_generation_input_state patched-run3 true "$input_state_dir/patched-run3.json"
generate_headers "$canonical_node" "$canonical_full" "$output_dir/evidence/generated-headers/repeat-2" true

node - "$input_state_dir" <<'NODE'
const { readFileSync, writeFileSync } = require("node:fs");
const { join } = require("node:path");
const names = ["patched-run1", "patched-run2", "patched-run3"];
const runs = names.map((name) => JSON.parse(readFileSync(join(process.argv[2], `${name}.json`), "utf8")));
const comparable = (run) => ({
  patched: run.patched,
  indexPopulated: run.indexPopulated,
  indexedFileCount: run.indexedFileCount,
  untrackedFilesAbsent: run.untrackedFilesAbsent,
  worktreeMatchesIndex: run.worktreeMatchesIndex,
  configTreeSha256: run.configTreeSha256,
  fullOpenSslTreeSha256: run.fullOpenSslTreeSha256,
  vendoredOpenSslTreeSha256: run.vendoredOpenSslTreeSha256,
  environment: run.environment,
});
const reference = JSON.stringify(comparable(runs[0]));
if (!runs.every((run) => JSON.stringify(comparable(run)) === reference)) {
  throw new Error("independently reconstructed patched generator inputs differ");
}
writeFileSync(join(process.argv[2], "PATCHED_INPUT_STATE_COMPARISON.json"), `${JSON.stringify({
  schemaVersion: 1,
  runs: names,
  independentlyReconstructed: true,
  canonicalPathPolicy: "one reconstructed source path reused only after complete reset",
  identical: true,
}, null, 2)}\n`);
NODE

cmp "$output_dir/evidence/generated-headers/patched/SHA256SUMS" "$output_dir/evidence/generated-headers/repeat/SHA256SUMS"
cmp "$output_dir/evidence/generated-headers/repeat/SHA256SUMS" "$output_dir/evidence/generated-headers/repeat-2/SHA256SUMS"
cmp "$output_dir/evidence/generated-headers/patched/SHA256SUMS" "$output_dir/evidence/generated-headers/repeat-2/SHA256SUMS"
(
  cd "$output_dir/evidence/generated-headers"
  diff -ruN baseline patched > ../GENERATED_HEADERS.diff || status=$?
  [[ ${status:-0} -eq 1 ]]
)
for header in \
  "$output_dir/evidence/generated-headers/patched/archs/linux-x86_64/asm/include/openssl/ssl.h" \
  "$output_dir/evidence/generated-headers/patched/archs/linux-aarch64/asm/include/openssl/ssl.h"; do
  grep -Fqx '#define SSL_VALUE_QUIC_MAX_PENDING_CONNS 16' "$header"
done

node - "$output_dir/evidence/GENERATED_HEADERS.json" <<'NODE'
const { createHash } = require("node:crypto");
const { readFileSync, writeFileSync } = require("node:fs");
const { dirname, join } = require("node:path");
const out = process.argv[2];
const base = dirname(out);
const hash = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
writeFileSync(out, `${JSON.stringify({
  schemaVersion: 1,
  generator: "make -C deps/openssl/config",
  architectures: ["linux-x86_64", "linux-aarch64"],
  macro: "SSL_VALUE_QUIC_MAX_PENDING_CONNS",
  macroValue: 16,
  baselineHeaderTreeSha256: hash(join(base, "generated-headers/baseline/SHA256SUMS")),
  patchedRun1HeaderTreeSha256: hash(join(base, "generated-headers/patched/SHA256SUMS")),
  patchedRun2HeaderTreeSha256: hash(join(base, "generated-headers/repeat/SHA256SUMS")),
  patchedRun3HeaderTreeSha256: hash(join(base, "generated-headers/repeat-2/SHA256SUMS")),
  reproducible: true,
  diffSha256: hash(join(base, "GENERATED_HEADERS.diff")),
}, null, 2)}\n`);
NODE

if (( headers_only )); then
  printf 'HEADER_GENERATION=%s\n' PASS
  exit 0
fi

(
  cd "$canonical_node"
  SOURCE_DATE_EPOCH="$source_date_epoch" ./configure --without-npm
  make -j"${JOBS:-2}"
)
node_binary="$canonical_node/out/Release/node"
[[ -x "$node_binary" ]] || { echo "Node build did not produce out/Release/node" >&2; exit 1; }
install -m 0755 "$node_binary" "$output_dir/nodejs/bin/node"
[[ "$("$output_dir/nodejs/bin/node" --version)" = "$expected_node_version" ]]
[[ "$("$output_dir/nodejs/bin/node" -p 'process.versions.openssl')" = "$expected_openssl_version" ]]

baseline_openssl_for_probe="$work_root/baseline-openssl-probe"
extract_openssl "$baseline_openssl_for_probe"
"$script_root/scripts/run-quic-pending-limit-regression.sh" "$arch" "$canonical_node" "$baseline_openssl_for_probe" "$output_dir/evidence"

readelf -h "$output_dir/nodejs/bin/node" > "$output_dir/evidence/ELF.txt"
readelf -d "$output_dir/nodejs/bin/node" > "$output_dir/evidence/DT_NEEDED.txt"
case "$arch" in
  amd64) grep -Fq 'Machine:                           Advanced Micro Devices X86-64' "$output_dir/evidence/ELF.txt"; expected_process_arch=x64 ;;
  arm64) grep -Fq 'Machine:                           AArch64' "$output_dir/evidence/ELF.txt"; expected_process_arch=arm64 ;;
esac
[[ "$("$output_dir/nodejs/bin/node" -p 'process.arch')" = "$expected_process_arch" ]]
mapfile -t needed < <(sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' "$output_dir/evidence/DT_NEEDED.txt")
for library in "${needed[@]}"; do
  case "$library" in
    libssl.so*|libcrypto.so*) echo "external OpenSSL dependency is forbidden: $library" >&2; exit 1 ;;
    libc.so.*|libm.so.*|libdl.so.*|libpthread.so.*|ld-linux-*.so.*) ;;
    libstdc++.so.*|libgcc_s.so.*)
      candidate="$(find /usr/lib /lib -type f -name "${library}*" -print -quit 2>/dev/null || true)"
      [[ -n "$candidate" ]] || { echo "required runtime closure library is unavailable: $library" >&2; exit 1; }
      destination="$output_dir/closure$(dirname "$candidate")"
      install -d -m 0755 "$destination"
      install -m 0755 "$candidate" "$destination/$library"
      ;;
    *) echo "unclassified dynamic dependency: $library" >&2; exit 1 ;;
  esac
done
if find "$output_dir" -type f \( -name 'libssl.so*' -o -name 'libcrypto.so*' \) -print -quit | grep -q .; then
  echo "runtime output contains an external OpenSSL library" >&2
  exit 1
fi

NODE_SHA256="$(sha256sum "$output_dir/nodejs/bin/node" | awk '{print $1}')" \
ARCH="$arch" \
PROCESS_ARCH="$expected_process_arch" \
SOURCE_REPOSITORY="${CERT_SOURCE_REPOSITORY:-local-static-validation}" \
SOURCE_COMMIT="${CERT_SOURCE_COMMIT:-local-static-validation}" \
SOURCE_REF="${CERT_SOURCE_REF:-local-static-validation}" \
WORKFLOW_PATH="${CERT_WORKFLOW_PATH:-local-static-validation}" \
WORKFLOW_COMMIT="${CERT_WORKFLOW_COMMIT:-local-static-validation}" \
RUN_ID="${CERT_RUN_ID:-0}" \
RUN_ATTEMPT="${CERT_RUN_ATTEMPT:-0}" \
node - "$manifest" "$output_dir/evidence/RUNTIME_PROVENANCE.json" <<'NODE'
const fs = require("node:fs");
const manifest = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const evidence = {
  schemaVersion: 1,
  runtimeIdentity: "custom-node-openssl-security-runtime",
  upstreamNode: manifest.node.version,
  upstreamNodeSourceSha256: manifest.node.sourceSha256,
  upstreamOpenSSLBasis: manifest.openssl.basis,
  upstreamOpenSSLSourceSha256: manifest.openssl.sourceSha256,
  cve: "CVE-2026-14456",
  opensslFixCommit: manifest.openssl.fixCommit,
  officialPatchSha256: manifest.openssl.officialPatchSha256,
  nodeAdaptedPatchSha256: manifest.openssl.adaptedPatchSha256,
  architecture: process.env.ARCH,
  processArch: process.env.PROCESS_ARCH,
  nodeSha256: process.env.NODE_SHA256,
  source: {
    repository: process.env.SOURCE_REPOSITORY,
    commit: process.env.SOURCE_COMMIT,
    ref: process.env.SOURCE_REF,
    workflowPath: process.env.WORKFLOW_PATH,
    workflowCommit: process.env.WORKFLOW_COMMIT,
    runId: process.env.RUN_ID,
    runAttempt: process.env.RUN_ATTEMPT,
  },
  headerGenerator: "make -C deps/openssl/config",
};
fs.writeFileSync(process.argv[3], `${JSON.stringify(evidence, null, 2)}\n`);
NODE
node - "$output_dir/evidence/ELF.json" "$output_dir/evidence/ELF.txt" "$arch" "$expected_process_arch" <<'NODE'
const fs = require("node:fs");
fs.writeFileSync(process.argv[2], `${JSON.stringify({
  schemaVersion: 1,
  architecture: process.argv[4],
  processArch: process.argv[5],
  readelfHeader: fs.readFileSync(process.argv[3], "utf8"),
}, null, 2)}\n`);
NODE
for file in LICENSE licenses/Node-LICENSE licenses/OpenSSL-LICENSE.txt licenses/MODIFICATION-NOTICE.md; do
  [[ -f "$script_root/$file" ]] || { echo "required public notice is absent: $file" >&2; exit 1; }
done
install -m 0644 "$script_root/LICENSE" "$output_dir/licenses/LICENSE"
install -m 0644 "$script_root/licenses/Node-LICENSE" "$output_dir/licenses/Node-LICENSE"
install -m 0644 "$script_root/licenses/OpenSSL-LICENSE.txt" "$output_dir/licenses/OpenSSL-LICENSE.txt"
install -m 0644 "$script_root/licenses/MODIFICATION-NOTICE.md" "$output_dir/licenses/MODIFICATION-NOTICE.md"
printf 'NODE_VERSION=%s\n' "$expected_node_version"
printf 'NODE_OPENSSL_VERSION=%s\n' "$expected_openssl_version"
printf 'NODE_ARCH=%s\n' "$expected_process_arch"
printf 'HEADER_GENERATION=%s\n' PASS

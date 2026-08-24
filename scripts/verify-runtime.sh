#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
umask 022

[[ $# -eq 2 ]] || { echo "usage: $0 <amd64|arm64> <runtime-dir>" >&2; exit 64; }
arch="$1"
runtime_dir="$2"
node_binary="$runtime_dir/nodejs/bin/node"
evidence="$runtime_dir/evidence"
provenance="$evidence/RUNTIME_PROVENANCE.json"
[[ -x "$node_binary" && -f "$provenance" ]] || { echo 'runtime files are incomplete' >&2; exit 1; }

case "$arch" in
  amd64) expected_uname=x86_64; expected_process=x64; expected_machine='Advanced Micro Devices X86-64' ;;
  arm64) expected_uname=aarch64; expected_process=arm64; expected_machine=AArch64 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 64 ;;
esac
[[ "$(uname -m)" = "$expected_uname" ]] || { echo "runner architecture mismatch" >&2; exit 1; }
[[ "$("$node_binary" --version)" = v22.23.2 ]]
[[ "$("$node_binary" -p 'process.versions.openssl')" = 3.5.7 ]]
[[ "$("$node_binary" -p 'process.arch')" = "$expected_process" ]]
readelf -h "$node_binary" | grep -Fq "Machine:                           $expected_machine"

node_count="$(find "$runtime_dir" -type f -name node | wc -l | tr -d ' ')"
[[ "$node_count" = 1 ]] || { echo "unexpected Node binary count: $node_count" >&2; exit 1; }
if find "$runtime_dir" -type f \( -name 'libssl.so*' -o -name 'libcrypto.so*' \) -print -quit | grep -q .; then
  echo 'runtime contains a forbidden external OpenSSL library' >&2
  exit 1
fi
for evidence_file in \
  PATCH_EQUIVALENCE.json GENERATED_HEADERS.json CVE_NEGATIVE_CONTROL.json CVE_POSITIVE_CONTROL.json \
  RUNTIME_PROVENANCE.json ELF.json DT_NEEDED.txt; do
  [[ -f "$evidence/$evidence_file" ]] || { echo "missing evidence: $evidence_file" >&2; exit 1; }
done
node - "$provenance" "$arch" "$expected_process" <<'NODE'
const fs = require("node:fs");
const [path, arch, processArch] = process.argv.slice(2);
const p = JSON.parse(fs.readFileSync(path, "utf8"));
const required = {
  runtimeIdentity: "custom-node-openssl-security-runtime",
  upstreamNode: "22.23.2",
  upstreamOpenSSLBasis: "3.5.7",
  cve: "CVE-2026-14456",
  opensslFixCommit: "08e7756c3900bcfd77a720e7b74e27d6e4ed01a9",
  nodeAdaptedPatchSha256: "b23805accae194a81fb43f07c1fbac8fdb13a4d267ef7e687bfb800241581d01",
  architecture: arch,
  processArch,
};
for (const [key, value] of Object.entries(required)) {
  if (p[key] !== value) throw new Error(`runtime provenance mismatch: ${key}`);
}
for (const key of ["repository", "commit", "ref", "workflowPath", "workflowCommit", "runId", "runAttempt"]) {
  if (!p.source || typeof p.source[key] !== "string" || !p.source[key]) throw new Error(`runtime source identity is incomplete: ${key}`);
}
NODE
node - "$evidence/CVE_NEGATIVE_CONTROL.json" "$evidence/CVE_POSITIVE_CONTROL.json" "$arch" <<'NODE'
const fs = require("node:fs");
const negative = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const positive = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
const arch = process.argv[4];
if (negative.result !== "FAIL_AS_EXPECTED" || negative.architecture !== arch) throw new Error("unpatched negative control is invalid");
if (positive.result !== "PASS" || positive.architecture !== arch || positive.defaultMaxPendingConnections !== 256) throw new Error("patched positive control is invalid");
NODE
printf 'RUNTIME_ARCH=%s\n' "$arch"
printf 'NODE_VERSION=%s\n' "$("$node_binary" --version)"
printf 'NODE_OPENSSL_VERSION=%s\n' "$("$node_binary" -p 'process.versions.openssl')"
printf 'RUNTIME_VERIFICATION=PASS\n'

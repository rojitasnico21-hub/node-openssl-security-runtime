#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
umask 022

[[ $# -eq 4 ]] || { echo "usage: $0 <amd64|arm64> <patched-node-root> <baseline-openssl-root> <evidence-dir>" >&2; exit 64; }
arch="$1"
node_root="$2"
baseline_root="$3"
evidence_dir="$4"
script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
probe="$script_root/tests/quic_pending_limit_probe.c"
mkdir -p "$evidence_dir"

case "$arch" in
  amd64) openssl_target=linux-x86_64; generated_arch=linux-x86_64 ;;
  arm64) openssl_target=linux-aarch64; generated_arch=linux-aarch64 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 64 ;;
esac

for tool in cc make ar find sha256sum node; do command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }; done
[[ -f "$probe" ]] || { echo "probe source is absent" >&2; exit 1; }

find_archive() {
  local root="$1" archive
  archive="$(find "$root/out/Release" -type f -name 'openssl.a' -print -quit 2>/dev/null || true)"
  [[ -n "$archive" && -f "$archive" ]] || { echo "Node OpenSSL archive is absent" >&2; exit 1; }
  ar t "$archive" | grep -Eq '(^|/)quic_port\.o$' || { echo "Node OpenSSL archive lacks quic_port.o" >&2; exit 1; }
  printf '%s' "$archive"
}

compile_probe() {
  local label="$1" include_root="$2" config_include="$3" ssl_archive="$4" crypto_archive="$5" binary="$6"
  cc -std=c11 -Wall -Wextra -Werror \
    -I"$include_root" -I"$config_include" \
    "$probe" "$ssl_archive" "$crypto_archive" -ldl -pthread -lz -o "$binary"
  "$binary"
  printf '%s\n' "${label}=PASS"
}

# The negative control is a fresh OpenSSL 3.5.7 tree with no patch. It runs the
# same public listener contract and therefore must fail; a green Trivy result
# cannot turn this control into a certification pass.
(
  cd "$baseline_root"
  ./Configure "$openssl_target" no-shared no-apps no-tests
  make -j"${JOBS:-2}" build_libs
)
baseline_ssl="$baseline_root/libssl.a"
baseline_crypto="$baseline_root/libcrypto.a"
[[ -f "$baseline_ssl" && -f "$baseline_crypto" ]] || { echo "baseline OpenSSL archives are absent" >&2; exit 1; }
if compile_probe baseline "$baseline_root/include" "$baseline_root/include" "$baseline_ssl" "$baseline_crypto" "$evidence_dir/baseline-probe"; then
  echo "unpatched baseline unexpectedly satisfied the fixed capacity contract" >&2
  exit 1
fi

node_ssl_archive="$(find_archive "$node_root")"
node_crypto_archive="$node_ssl_archive"
config_include="$node_root/deps/openssl/config/archs/$generated_arch/asm/include"
[[ -d "$config_include" ]] || { echo "Node generated config include is absent" >&2; exit 1; }
compile_probe patched "$node_root/deps/openssl/openssl/include" "$config_include" "$node_ssl_archive" "$node_crypto_archive" "$evidence_dir/patched-probe"

guard_source="$node_root/deps/openssl/openssl/ssl/quic/quic_port.c"
grep -Fqx '#define DEFAULT_MAX_PENDING_CONNS 256' "$guard_source"
grep -Fq 'ossl_list_incoming_ch_num(&port->incoming_channel_list) >= port->max_pending_channels' "$guard_source"

NODE_OPENSSL_ARCHIVE="$node_ssl_archive" \
BASELINE_SSL_ARCHIVE="$baseline_ssl" \
ARCH="$arch" \
node - "$evidence_dir" <<'NODE'
const { createHash } = require("node:crypto");
const { readFileSync, writeFileSync } = require("node:fs");
const { join } = require("node:path");
const hash = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const out = process.argv[2];
writeFileSync(join(out, "CVE_NEGATIVE_CONTROL.json"), `${JSON.stringify({
  schemaVersion: 1,
  cve: "CVE-2026-14456",
  architecture: process.env.ARCH,
  result: "FAIL_AS_EXPECTED",
  test: "QUIC listener pending-capacity API contract",
  baselineOpenSslArchiveSha256: hash(process.env.BASELINE_SSL_ARCHIVE),
}, null, 2)}\n`);
writeFileSync(join(out, "CVE_POSITIVE_CONTROL.json"), `${JSON.stringify({
  schemaVersion: 1,
  cve: "CVE-2026-14456",
  architecture: process.env.ARCH,
  result: "PASS",
  test: "QUIC listener pending-capacity API contract",
  defaultMaxPendingConnections: 256,
  sourceGuard: "incoming queue is rejected at configured maximum",
  nodeOpenSslArchiveSha256: hash(process.env.NODE_OPENSSL_ARCHIVE),
}, null, 2)}\n`);
NODE

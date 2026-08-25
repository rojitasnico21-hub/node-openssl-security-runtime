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

for tool in cc make ar find sha256sum node awk; do command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }; done
[[ -f "$probe" ]] || { echo "probe source is absent" >&2; exit 1; }

find_archive() {
  local root="$1" release expected_archive expected_quic_object candidate quic_member_count
  local -a candidates=()

  [[ -d "$root" ]] || { echo "Node build tree is absent" >&2; exit 1; }
  root="$(cd "$root" && pwd -P)"
  release="$root/out/Release"
  expected_archive="$release/obj.target/deps/openssl/libopenssl.a"
  expected_quic_object="$release/obj.target/openssl/deps/openssl/openssl/ssl/quic/quic_port.o"

  if [[ -d "$release" ]]; then
    while IFS= read -r candidate; do
      [[ -n "$candidate" ]] && candidates+=("$candidate")
    done < <(
      find "$release" -type f \( -name 'libopenssl.a' -o -name 'openssl.a' \) -print |
        LC_ALL=C sort
    )
  fi

  if (( ${#candidates[@]} != 1 )); then
    echo "expected exactly one Node OpenSSL archive in the current build tree; found ${#candidates[@]}" >&2
    if (( ${#candidates[@]} > 0 )); then
      printf 'archive candidate: %s\n' "${candidates[@]}" >&2
    fi
    exit 1
  fi
  [[ "${candidates[0]}" = "$expected_archive" ]] || {
    echo "unexpected Node OpenSSL archive path: ${candidates[0]}" >&2
    echo "expected: $expected_archive" >&2
    exit 1
  }
  [[ -f "$expected_quic_object" ]] || {
    echo "Node OpenSSL quic_port.o object is absent from the current build tree" >&2
    exit 1
  }

  quic_member_count="$(ar t "$expected_archive" | awk '$0 ~ /(^|\/)quic_port[.]o$/ { count++ } END { print count + 0 }')"
  [[ "$quic_member_count" = 1 ]] || {
    echo "Node OpenSSL archive must contain exactly one quic_port.o member; found $quic_member_count" >&2
    exit 1
  }
  printf '%s\n' "$expected_archive"
}

compile_probe() {
  local include_root="$1" config_include="$2" ssl_archive="$3" crypto_archive="$4" binary="$5"
  cc -std=c11 -Wall -Wextra -Werror \
    -I"$include_root" -I"$config_include" \
    "$probe" "$ssl_archive" "$crypto_archive" -ldl -pthread -lz -o "$binary"
}

run_probe() {
  local binary="$1" rc
  if "$binary"; then
    rc=0
  else
    rc=$?
  fi
  return "$rc"
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
if ! compile_probe "$baseline_root/include" "$baseline_root/include" "$baseline_ssl" "$baseline_crypto" "$evidence_dir/baseline-probe"; then
  echo "baseline probe compilation failed; negative control is invalid" >&2
  exit 1
fi
if run_probe "$evidence_dir/baseline-probe"; then
  baseline_rc=0
else
  baseline_rc=$?
fi
case "$baseline_rc" in
  1)
    printf '%s\n' 'baseline=FAIL_AS_EXPECTED'
    ;;
  0)
    echo "unpatched baseline unexpectedly satisfied the fixed capacity contract" >&2
    exit 1
    ;;
  *)
    echo "baseline probe execution failed with exit code ${baseline_rc}; negative control is invalid" >&2
    exit 1
    ;;
esac

node_root="$(cd "$node_root" && pwd -P)"
node_ssl_archive="$(find_archive "$node_root")"
node_crypto_archive="$node_ssl_archive"
node_quic_object="$node_root/out/Release/obj.target/openssl/deps/openssl/openssl/ssl/quic/quic_port.o"
node_quic_archive_member="$(ar t "$node_ssl_archive" | awk '$0 ~ /(^|\/)quic_port[.]o$/ && member == "" { member = $0 } END { print member }')"
[[ -n "$node_quic_archive_member" ]] || { echo "Node OpenSSL archive quic_port.o member cannot be identified" >&2; exit 1; }
node_quic_archive_member_relative="${node_quic_archive_member#"$node_root/"}"
case "$node_quic_archive_member_relative" in
  /*|../*|*/../*) echo "Node OpenSSL archive member escapes the current build tree" >&2; exit 1 ;;
esac
node_quic_object_sha256="$(sha256sum "$node_quic_object" | awk '{ print $1 }')"
node_ssl_archive_relative="${node_ssl_archive#"$node_root/"}"
node_quic_object_relative="${node_quic_object#"$node_root/"}"
config_include="$node_root/deps/openssl/config/archs/$generated_arch/asm/include"
[[ -d "$config_include" ]] || { echo "Node generated config include is absent" >&2; exit 1; }
if ! compile_probe "$node_root/deps/openssl/openssl/include" "$config_include" "$node_ssl_archive" "$node_crypto_archive" "$evidence_dir/patched-probe"; then
  echo "patched probe compilation failed" >&2
  exit 1
fi
if run_probe "$evidence_dir/patched-probe"; then
  patched_rc=0
else
  patched_rc=$?
fi
case "$patched_rc" in
  0)
    printf '%s\n' 'patched=PASS'
    ;;
  1)
    echo "patched probe failed the fixed capacity contract" >&2
    exit 1
    ;;
  *)
    echo "patched probe execution failed with exit code ${patched_rc}" >&2
    exit 1
    ;;
esac

guard_source="$node_root/deps/openssl/openssl/ssl/quic/quic_port.c"
grep -Fqx '#define DEFAULT_MAX_PENDING_CONNS 256' "$guard_source"
grep -Fq 'ossl_list_incoming_ch_num(&port->incoming_channel_list) >= port->max_pending_channels' "$guard_source"

NODE_OPENSSL_ARCHIVE="$node_ssl_archive" \
NODE_OPENSSL_ARCHIVE_RELATIVE="$node_ssl_archive_relative" \
NODE_OPENSSL_ARCHIVE_MEMBER="$node_quic_archive_member_relative" \
NODE_OPENSSL_QUIC_OBJECT_RELATIVE="$node_quic_object_relative" \
NODE_OPENSSL_QUIC_OBJECT_SHA256="$node_quic_object_sha256" \
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
  nodeOpenSslArchivePath: process.env.NODE_OPENSSL_ARCHIVE_RELATIVE,
  nodeOpenSslArchiveMemberQuicPort: process.env.NODE_OPENSSL_ARCHIVE_MEMBER,
  nodeOpenSslQuicObjectPath: process.env.NODE_OPENSSL_QUIC_OBJECT_RELATIVE,
  nodeOpenSslQuicObjectSha256: process.env.NODE_OPENSSL_QUIC_OBJECT_SHA256,
  nodeOpenSslArchiveSha256: hash(process.env.NODE_OPENSSL_ARCHIVE),
}, null, 2)}\n`);
NODE

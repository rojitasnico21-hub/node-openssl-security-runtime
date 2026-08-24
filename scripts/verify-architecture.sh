#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

[[ $# -eq 3 ]] || { echo "usage: $0 <amd64|arm64> <node-binary> <provenance.json>" >&2; exit 64; }
arch="$1"; node_binary="$2"; provenance="$3"
case "$arch" in
  amd64) expected_uname=x86_64; expected_node=x64; expected_elf='Advanced Micro Devices X86-64' ;;
  arm64) expected_uname=aarch64; expected_node=arm64; expected_elf=AArch64 ;;
  *) exit 64 ;;
esac
[[ "$(uname -m)" = "$expected_uname" ]] || { echo "uname architecture mismatch" >&2; exit 1; }
[[ "$("$node_binary" -p 'process.arch')" = "$expected_node" ]] || { echo "Node process.arch mismatch" >&2; exit 1; }
readelf -h "$node_binary" | grep -Fq "Machine:                           $expected_elf"
node - "$provenance" "$arch" "$expected_node" <<'NODE'
const fs = require('node:fs');
const [file, architecture, processArch] = process.argv.slice(2);
const p = JSON.parse(fs.readFileSync(file, 'utf8'));
if (p.architecture !== architecture || p.processArch !== processArch) throw new Error('provenance architecture mismatch');
NODE
printf 'ARCHITECTURE_BINDING=%s\n' PASS

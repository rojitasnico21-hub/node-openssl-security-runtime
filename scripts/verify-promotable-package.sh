#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

[[ $# -eq 3 ]] || { echo "usage: $0 <runtime-dir> <expected-arch> <trusted-commit>" >&2; exit 64; }
runtime="$1"; arch="$2"; commit="$3"
for tool in sha256sum node find grep; do command -v "$tool" >/dev/null || exit 1; done
[[ -f "$runtime/SHA256SUMS" && -x "$runtime/nodejs/bin/node" ]] || { echo 'runtime package is incomplete' >&2; exit 1; }
(cd "$runtime" && sha256sum -c SHA256SUMS)
node - "$runtime/evidence/RUNTIME_PROVENANCE.json" "$runtime/evidence/CVE_NEGATIVE_CONTROL.json" "$runtime/evidence/CVE_POSITIVE_CONTROL.json" "$arch" "$commit" <<'NODE'
const fs = require('node:fs');
const [pfile, negativeFile, positiveFile, arch, commit] = process.argv.slice(2);
const p = JSON.parse(fs.readFileSync(pfile, 'utf8'));
const negative = JSON.parse(fs.readFileSync(negativeFile, 'utf8'));
const positive = JSON.parse(fs.readFileSync(positiveFile, 'utf8'));
if (p.architecture !== arch || p.source.commit !== commit || p.source.repository !== 'rojitasnico21-hub/node-openssl-security-runtime' || p.source.ref !== 'refs/heads/main') throw new Error('untrusted package identity');
if (negative.result !== 'FAIL_AS_EXPECTED' || positive.result !== 'PASS' || positive.defaultMaxPendingConnections !== 256) throw new Error('CVE behavioral gate is incomplete');
NODE
if find "$runtime" -type f \( -name 'libssl.so*' -o -name 'libcrypto.so*' \) -print -quit | grep -q .; then
  echo 'runtime package contains external OpenSSL libraries' >&2
  exit 1
fi
printf 'PROMOTION_PACKAGE_POLICY=%s\n' PASS

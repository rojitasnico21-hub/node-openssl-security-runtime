#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 1 ]] || { echo "usage: $0 <runtime-dir>" >&2; exit 64; }
runtime_dir="$1"
node_binary="$runtime_dir/bin/node"
provenance="$runtime_dir/AUTOMATED_RUNTIME_PROVENANCE.json"
[[ -x "$node_binary" && -f "$provenance" ]] || { echo 'runtime files are incomplete' >&2; exit 1; }

node_count="$(find "$runtime_dir" -type f -name node | wc -l | tr -d ' ')"
[[ "$node_count" = 1 ]] || { echo "unexpected Node binary count: $node_count" >&2; exit 1; }

[[ "$("$node_binary" --version)" = v22.23.2 ]]
[[ "$("$node_binary" -p 'process.versions.openssl')" = 3.5.7 ]]
grep -Fqx '"upstreamNode": "22.23.2",' "$provenance"
grep -Fqx '"upstreamOpenSSLBasis": "3.5.7",' "$provenance"
grep -Fqx '"cve": "CVE-2026-14456",' "$provenance"
grep -Fqx '"opensslFixCommit": "08e7756c3900bcfd77a720e7b74e27d6e4ed01a9",' "$provenance"
grep -Fqx '"adaptedPatchSha256": "b23805accae194a81fb43f07c1fbac8fdb13a4d267ef7e687bfb800241581d01",' "$provenance"

command -v readelf >/dev/null || { echo 'readelf is required for dependency audit' >&2; exit 1; }
readelf -d "$node_binary" > "$runtime_dir/readelf.dynamic.txt"
if grep -Eq 'libssl|libcrypto' "$runtime_dir/readelf.dynamic.txt"; then
  echo 'external OpenSSL dependency requires separate audit' >&2
  exit 1
fi
if find "$runtime_dir" -type f \( -name 'libssl.so*' -o -name 'libcrypto.so*' \) -print -quit | grep -q .; then
  echo 'runtime contains an unclassified external OpenSSL library' >&2
  exit 1
fi

sha256sum "$node_binary" "$provenance" > "$runtime_dir/runtime.sha256"
printf 'NODE_VERSION=%s\n' "$("$node_binary" --version)"
printf 'NODE_OPENSSL_VERSION=%s\n' "$("$node_binary" -p 'process.versions.openssl')"
printf 'EXTERNAL_OPENSSL_DEPENDENCY=NONE\n'

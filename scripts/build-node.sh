#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s [--headers-only] <amd64|arm64> <node.tar.xz> <openssl.tar.gz> <adapted.patch> <output-dir>\n' "$0" >&2
  exit 64
}

headers_only=0
if [[ ${1:-} = --headers-only ]]; then
  headers_only=1
  shift
fi
[[ $# -eq 5 ]] || usage

arch="$1"
node_tar="$2"
openssl_tar="$3"
patch_file="$4"
output_dir="$5"
case "$arch" in
  amd64) target_arch=x86_64 ;;
  arm64) target_arch=aarch64 ;;
  *) usage ;;
esac

readonly expected_node_sha='bbe768df8d5815d7fa76124052985332452e0a4742d39f32027550d1aab8f6fb'
readonly expected_openssl_sha='d71a811bfbd9153d7b30cbe476263302ee4b04a9a47ffea6e6a782326805c93f'
readonly expected_patch_sha='b23805accae194a81fb43f07c1fbac8fdb13a4d267ef7e687bfb800241581d01'
readonly expected_fix_commit='08e7756c3900bcfd77a720e7b74e27d6e4ed01a9'
readonly expected_node_version='v22.23.2'
readonly expected_openssl_version='3.5.7'

for tool in sha256sum tar git make sed grep find install mkdir mktemp cp rm sort xargs awk getconf; do
  command -v "$tool" >/dev/null || { printf 'missing required tool: %s\n' "$tool" >&2; exit 1; }
done
printf '%s  %s\n' "$expected_node_sha" "$node_tar" | sha256sum -c -
printf '%s  %s\n' "$expected_openssl_sha" "$openssl_tar" | sha256sum -c -
printf '%s  %s\n' "$expected_patch_sha" "$patch_file" | sha256sum -c -

mkdir -p "$output_dir"
work_root="$(mktemp -d "${TMPDIR:-/tmp}/patched-node.XXXXXX")"
cleanup() { rm -rf "$work_root"; }
trap cleanup EXIT

tar -C "$work_root" -xJf "$node_tar"
source_root="$work_root/node-v22.23.2"
[[ -d "$source_root/deps/openssl/openssl" ]] || { echo 'Node source tree is incomplete' >&2; exit 1; }

full_openssl="$work_root/openssl-full"
mkdir -p "$full_openssl"
tar -C "$full_openssl" --strip-components=1 -xzf "$openssl_tar"
node_openssl="$source_root/deps/openssl/openssl"

for openssl_tree in "$node_openssl" "$full_openssl"; do
  (
    cd "$openssl_tree"
    git apply --check --verbose "$patch_file"
    git apply --verbose "$patch_file"
    ! find . -name '*.rej' -type f -print -quit | grep -q .
  )
done

mv "$node_openssl" "$work_root/openssl-pruned"
mv "$full_openssl" "$node_openssl"
git init -q "$source_root"
git -C "$source_root" add -A
make -C "$source_root/deps/openssl/config" clean
sed -i 's/#ifdef/%ifdef/g' "$node_openssl/crypto/perlasm/x86asm.pl"
sed -i 's/#endif/%endif/g' "$node_openssl/crypto/perlasm/x86asm.pl"
PATH="/opt/nasm/usr/bin:$PATH" make -C "$source_root/deps/openssl/config"

grep -Fqx '#include "../../../config/ssl.h"' "$node_openssl/include/openssl/ssl.h"
for header in \
  "$source_root/deps/openssl/config/archs/linux-x86_64/asm/include/openssl/ssl.h" \
  "$source_root/deps/openssl/config/archs/linux-x86_64/no-asm/include/openssl/ssl.h" \
  "$source_root/deps/openssl/config/archs/linux-aarch64/asm/include/openssl/ssl.h" \
  "$source_root/deps/openssl/config/archs/linux-aarch64/no-asm/include/openssl/ssl.h"; do
  grep -Fqx '#define SSL_VALUE_QUIC_MAX_PENDING_CONNS 16' "$header"
done

cp "$node_openssl/include/openssl/ssl.h" "$work_root/openssl-pruned/include/openssl/ssl.h"
mv "$node_openssl" "$work_root/openssl-generated"
mv "$work_root/openssl-pruned" "$source_root/deps/openssl/openssl"

if (( headers_only )); then
  install -d "$output_dir/headers/$arch"
  cp -R "$source_root/deps/openssl/config/archs/." "$output_dir/headers/$arch/"
  find "$output_dir/headers/$arch" -type f -print0 | sort -z | xargs -0 sha256sum
  printf 'HEADER_GENERATION=%s\n' PASS
  exit 0
fi

(
  cd "$source_root"
  ./configure --without-npm
  make -j"${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}"
)

node_binary="$source_root/out/Release/node"
[[ -x "$node_binary" ]] || { echo 'Node build did not produce out/Release/node' >&2; exit 1; }
install -d "$output_dir/bin"
install -m 0755 "$node_binary" "$output_dir/bin/node"
node_version="$("$output_dir/bin/node" --version)"
openssl_version="$("$output_dir/bin/node" -p 'process.versions.openssl')"
[[ "$node_version" = "$expected_node_version" ]]
[[ "$openssl_version" = "$expected_openssl_version" ]]

patch_sha="$(sha256sum "$patch_file" | awk '{print $1}')"
cat > "$output_dir/AUTOMATED_RUNTIME_PROVENANCE.json" <<EOF
{
  "upstreamNode": "22.23.2",
  "upstreamOpenSSLBasis": "3.5.7",
  "cve": "CVE-2026-14456",
  "opensslFixCommit": "$expected_fix_commit",
  "adaptedPatchSha256": "$patch_sha",
  "headerGenerator": "make -C deps/openssl/config",
  "architecture": "$arch"
}
EOF
sha256sum "$output_dir/bin/node" > "$output_dir/node.sha256"
sha256sum "$output_dir/AUTOMATED_RUNTIME_PROVENANCE.json" > "$output_dir/provenance.sha256"

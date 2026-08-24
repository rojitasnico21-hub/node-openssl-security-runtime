#!/usr/bin/env node
/** SPDX-License-Identifier: Apache-2.0 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const read = (path) => readFileSync(resolve(root, path), "utf8");
const fail = (message) => { throw new Error(`PUBLICATION_POLICY_ERROR=${message}`); };
const certify = read(".github/workflows/certify.yml");
const publish = read(".github/workflows/publish.yml");
const dockerBuilder = read("Dockerfile.builder");
const dockerRuntime = read("Dockerfile.runtime");

for (const [name, text] of [["certify", certify], ["publish", publish]]) {
  if (!/^on:\n  workflow_dispatch:/m.test(text)) fail(`${name} must be workflow_dispatch-only`);
  if (/pull_request_target|pull_request:|^  push:/m.test(text)) fail(`${name} has an untrusted automatic trigger`);
}
if (!/permissions:\n  contents: read\n/m.test(certify)) fail("certification lacks global read-only permission");
if (/packages: write|id-token: write|contents: write|attestations: write/.test(certify)) fail("certification has promotion permission");
if ((certify.match(/docker buildx build/g) || []).length !== 2) fail("expected exactly two Buildx invocations");
if ((certify.match(/--file "\$context\/Dockerfile\.builder"/g) || []).length !== 2) fail("every Buildx invocation must select Dockerfile.builder");
if (/aquasecurity\/trivy-action|--ignore-unfixed|\.trivyignore|continue-on-error|severity:.*LOW/i.test(certify)) fail("certification weakens the Trivy gate");
if (!/scripts\/install-trivy\.sh/.test(certify) || !/TRIVY_DB\.json/.test(certify)) fail("Trivy binary or database identity is not retained");
if (!/needs: \[policy, headers\]/.test(certify)) fail("runtime build is not gated by policy and headers");
if (!/if: success\(\)/.test(certify) || !/if: failure\(\)/.test(certify)) fail("success package and failure diagnostics are not separated");
if (!/github\.repository/.test(certify) || !/GITHUB_WORKFLOW_REF/.test(certify) || !/refs\/heads\/main/.test(certify)) fail("trusted-main identity gate is incomplete");
if (!/verify-architecture\.sh/.test(certify) || !/CVE_NEGATIVE_CONTROL/.test(read("scripts/verify-runtime.sh"))) fail("architecture or behavioral CVE gate is absent");
if (!/FROM \$\{RUNTIME_BASE\}/.test(dockerRuntime) || !/base-nossl-debian12@sha256:/.test(dockerRuntime)) fail("runtime base is not digest-pinned no-SSL distroless");
if (!/COPY nodejs \/nodejs/.test(dockerRuntime) || /nodejs22/.test(dockerRuntime)) fail("runtime Dockerfile could reintroduce a vendor Node runtime");
if (!/find \"\$root\" -type f/.test(read("scripts/verify-runtime-image.sh"))) fail("final image OpenSSL inventory gate is absent");
if (!/^# syntax=docker\/dockerfile:1\.7@sha256:/m.test(dockerBuilder) || !/buildx-stable-1@sha256:/.test(read("BUILD_MANIFEST.json"))) fail("Dockerfile frontend or BuildKit is not pinned");

for (const file of ["LICENSE", "licenses/Node-LICENSE", "licenses/OpenSSL-LICENSE.txt", "licenses/MODIFICATION-NOTICE.md"]) {
  if (read(file).trim().length === 0) fail(`required notice is empty: ${file}`);
}
if (!/Apache License[\s\S]*Version 2\.0/.test(read("LICENSE"))) fail("builder Apache-2.0 text is incomplete");
if (!/CVE-2026-14456/.test(read("licenses/MODIFICATION-NOTICE.md"))) fail("modification notice lacks CVE identity");
if (!/runtime-image:/.test(publish) || !/needs: \[validate, runtime-image\]/.test(publish)) fail("promotion is not gated by trusted validation and both architecture images");
if (!/packages: write/.test(publish) || !/id-token: write/.test(publish) || !/attestations: write/.test(publish)) fail("promotion permissions are not scoped to promotion job");
if (/packages: write|id-token: write|attestations: write/.test(publish.slice(0, publish.indexOf("jobs:")))) fail("promotion permission is global");
if (!/verify-promotable-package\.sh/.test(publish) || !/refs\/heads\/main/.test(publish)) fail("promotion lacks trusted package/source verification");
if (!/candidate-\$\{\{ inputs\.certification_run_id \}\}-\$\{\{ matrix\.arch \}\}/.test(publish)) fail("uncertified runtime candidate is not isolated from immutable release tags");
if (!/install-cosign\.sh/.test(publish) || !/cosign" attest --yes/.test(publish)) fail("signed aggregate provenance is absent");
if (!/gh release create/.test(publish) || !/AGGREGATE_MANIFEST\.json/.test(publish)) fail("durable release mirror is absent");

process.stdout.write("PUBLICATION_POLICY=PASS\n");

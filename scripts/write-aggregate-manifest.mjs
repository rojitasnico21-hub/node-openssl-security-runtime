#!/usr/bin/env node
/** SPDX-License-Identifier: Apache-2.0 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const [out, sourceCommit, releaseTag, amd64Dir, arm64Dir] = process.argv.slice(2);
if (![out, sourceCommit, releaseTag, amd64Dir, arm64Dir].every(Boolean)) throw new Error("usage: write-aggregate-manifest.mjs OUT COMMIT TAG AMD64_DIR ARM64_DIR");
const hash = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const evidence = (dir, arch) => {
  const base = resolve(dir);
  const provenance = JSON.parse(readFileSync(resolve(base, "evidence/RUNTIME_PROVENANCE.json"), "utf8"));
  if (provenance.architecture !== arch || provenance.source.commit !== sourceCommit) throw new Error("untrusted " + arch + " runtime evidence");
  return {
    architecture: arch,
    nodeSha256: provenance.nodeSha256,
    runtimeProvenanceSha256: hash(resolve(base, "evidence/RUNTIME_PROVENANCE.json")),
    sbomSha256: hash(resolve(base, "evidence/SBOM.cdx.json")),
    trivySha256: hash(resolve(base, "evidence/TRIVY.json")),
    trivyDbSha256: hash(resolve(base, "evidence/TRIVY_DB.json")),
    patchProofSha256: hash(resolve(base, "evidence/PATCH_EQUIVALENCE.json")),
    generatedHeaderProofSha256: hash(resolve(base, "evidence/GENERATED_HEADERS.json")),
    cveNegativeControlSha256: hash(resolve(base, "evidence/CVE_NEGATIVE_CONTROL.json")),
    cvePositiveControlSha256: hash(resolve(base, "evidence/CVE_POSITIVE_CONTROL.json")),
  };
};
const manifest = {
  schemaVersion: 1,
  runtimeIdentity: "custom-node-openssl-security-runtime",
  sourceCommit,
  releaseTag,
  cve: "CVE-2026-14456",
  certification: [evidence(amd64Dir, "amd64"), evidence(arm64Dir, "arm64")],
};
writeFileSync(resolve(out), JSON.stringify(manifest, null, 2) + "\n");

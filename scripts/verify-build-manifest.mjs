#!/usr/bin/env node
/**
 * SPDX-License-Identifier: Apache-2.0
 *
 * Enforces the public source, patch-adaptation, and pinned-toolchain contract.
 * It deliberately compares raw unified-diff file sections: every retained
 * section must be byte-identical to the official OpenSSL patch.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

function die(message) {
  process.stderr.write(`BUILD_MANIFEST_POLICY_ERROR=${message}\n`);
  process.exit(1);
}

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function sections(buffer) {
  const text = buffer.toString("utf8");
  const matches = [...text.matchAll(/^diff --git a\/(.+) b\/(.+)$/gm)];
  if (matches.length === 0) die("patch has no unified diff sections");
  return new Map(matches.map((match, index) => {
    const start = match.index;
    const end = index + 1 < matches.length ? matches[index + 1].index : text.length;
    if (match[1] !== match[2]) die(`rename/copy section is unsupported: ${match[0]}`);
    return [match[1], Buffer.from(text.slice(start, end), "utf8")];
  }));
}

function assertString(value, name) {
  if (typeof value !== "string" || value.length === 0) die(`${name} is absent`);
}

const args = process.argv.slice(2);
const outIndex = args.indexOf("--out");
const output = outIndex === -1 ? null : args[outIndex + 1];
if (outIndex !== -1 && !output) die("--out requires a path");
const positional = outIndex === -1
  ? args
  : args.filter((_, index) => index !== outIndex && index !== outIndex + 1);
if (positional.length !== 3) {
  die("usage: verify-build-manifest.mjs [--out proof.json] BUILD_MANIFEST.json official.patch adapted.patch");
}

const [manifestPath, officialPath, adaptedPath] = positional.map((path) => resolve(path));
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
if (manifest.schemaVersion !== 2) die("unsupported manifest schema");

const requiredStrings = [
  [manifest.node?.version, "node.version"], [manifest.node?.sourceTagCommit, "node.sourceTagCommit"],
  [manifest.node?.sourceSha256, "node.sourceSha256"], [manifest.node?.sourceUrl, "node.sourceUrl"],
  [manifest.openssl?.basis, "openssl.basis"], [manifest.openssl?.sourceSha256, "openssl.sourceSha256"],
  [manifest.openssl?.sourceUrl, "openssl.sourceUrl"], [manifest.openssl?.fixCommit, "openssl.fixCommit"],
  [manifest.openssl?.officialPatchSha256, "openssl.officialPatchSha256"], [manifest.openssl?.officialPatchUrl, "openssl.officialPatchUrl"],
  [manifest.openssl?.adaptedPatchSha256, "openssl.adaptedPatchSha256"],
  [manifest.dependencies?.textTemplate?.package, "dependencies.textTemplate.package"],
  [manifest.dependencies?.textTemplate?.version, "dependencies.textTemplate.version"],
  [manifest.dependencies?.textTemplate?.architecture, "dependencies.textTemplate.architecture"],
  [manifest.dependencies?.textTemplate?.sha256, "dependencies.textTemplate.sha256"], [manifest.dependencies?.textTemplate?.url, "dependencies.textTemplate.url"],
  [manifest.dependencies?.nasm?.version, "dependencies.nasm.version"], [manifest.dependencies?.nasm?.urlBase, "dependencies.nasm.urlBase"],
  [manifest.dependencies?.nasm?.amd64?.package, "dependencies.nasm.amd64.package"], [manifest.dependencies?.nasm?.amd64?.sha256, "dependencies.nasm.amd64.sha256"],
  [manifest.dependencies?.nasm?.arm64?.package, "dependencies.nasm.arm64.package"], [manifest.dependencies?.nasm?.arm64?.sha256, "dependencies.nasm.arm64.sha256"],
  [manifest.toolchain?.dockerfileFrontend, "toolchain.dockerfileFrontend"], [manifest.toolchain?.buildx?.version, "toolchain.buildx.version"],
  [manifest.toolchain?.buildx?.amd64Sha256, "toolchain.buildx.amd64Sha256"], [manifest.toolchain?.buildx?.arm64Sha256, "toolchain.buildx.arm64Sha256"],
  [manifest.toolchain?.buildkitImage, "toolchain.buildkitImage"], [manifest.toolchain?.trivy?.version, "toolchain.trivy.version"],
  [manifest.toolchain?.trivy?.amd64Sha256, "toolchain.trivy.amd64Sha256"], [manifest.toolchain?.trivy?.arm64Sha256, "toolchain.trivy.arm64Sha256"],
  [manifest.toolchain?.cosign?.version, "toolchain.cosign.version"], [manifest.toolchain?.cosign?.checksumsSha256, "toolchain.cosign.checksumsSha256"],
  [manifest.toolchain?.cosign?.amd64Sha256, "toolchain.cosign.amd64Sha256"], [manifest.toolchain?.cosign?.arm64Sha256, "toolchain.cosign.arm64Sha256"],
];
for (const [value, name] of requiredStrings) assertString(value, name);
for (const [value, name] of requiredStrings) {
  if (name.endsWith("Sha256") && !/^[a-f0-9]{64}$/.test(value)) die(`${name} is not a SHA-256 hex value`);
}
for (const [name, image] of Object.entries(manifest.images ?? {})) {
  for (const key of ["image", "indexDigest", "amd64Digest", "arm64Digest"]) assertString(image?.[key], `images.${name}.${key}`);
  for (const key of ["indexDigest", "amd64Digest", "arm64Digest"]) if (!/^sha256:[a-f0-9]{64}$/.test(image[key])) die(`images.${name}.${key} is not a digest`);
}
if (!Number.isInteger(manifest.sourceDateEpoch) || manifest.sourceDateEpoch <= 0) die("sourceDateEpoch is invalid");

const official = readFileSync(officialPath);
const adapted = readFileSync(adaptedPath);
if (sha256(officialPath) !== manifest.openssl.officialPatchSha256) die("official patch SHA256 mismatch");
if (sha256(adaptedPath) !== manifest.openssl.adaptedPatchSha256) die("adapted patch SHA256 mismatch");
if (!official.toString("utf8").startsWith(`From ${manifest.openssl.fixCommit} `)) die("official patch commit mismatch");

const officialSections = sections(official);
const adaptedSections = sections(adapted);
const removedPaths = manifest.openssl.adaptation?.removedPaths;
if (!Array.isArray(removedPaths) || removedPaths.length !== 1) die("exactly one removed path is required");
const removed = new Set(removedPaths);
for (const path of removed) {
  if (!officialSections.has(path)) die(`removed path is absent from official patch: ${path}`);
  if (adaptedSections.has(path)) die(`removed path remains in adapted patch: ${path}`);
  if (!path.startsWith("doc/")) die(`removed path is not documentation: ${path}`);
}
for (const [path, section] of officialSections) {
  if (removed.has(path)) continue;
  const candidate = adaptedSections.get(path);
  if (!candidate) die(`required patch section is absent: ${path}`);
  if (!candidate.equals(section)) die(`retained section differs from official patch: ${path}`);
}
for (const path of adaptedSections.keys()) {
  if (!officialSections.has(path)) die(`adapted patch contains an unreviewed section: ${path}`);
}

const removedSections = [...removed].map((path) => officialSections.get(path).toString("utf8"));
const removedHunks = removedSections.reduce((count, section) => count + [...section.matchAll(/^@@ /gm)].length, 0);
const removedChangedLines = removedSections
  .flatMap((section) => section.split("\n"))
  .filter((line) => /^[+-]/.test(line) && !/^(\+\+\+|---)/.test(line));
if (manifest.openssl.adaptation.removedClassification !== "DOCUMENTATION_ONLY") die("removed content classification is not documentation-only");
if (manifest.openssl.adaptation.removedSecurityCodeLines !== 0 || manifest.openssl.adaptation.removedTestCodeLines !== 0) die("manifest permits non-documentation removal");
if (!manifest.openssl.adaptation.securityHunksByteIdentical) die("manifest does not require byte-identical security hunks");

const proof = {
  schemaVersion: 1,
  officialPatchSha256: sha256(officialPath),
  adaptedPatchSha256: sha256(adaptedPath),
  officialFixCommit: manifest.openssl.fixCommit,
  officialChangedFiles: [...officialSections.keys()].sort(),
  adaptedChangedFiles: [...adaptedSections.keys()].sort(),
  removedFiles: [...removed].sort(),
  removedHunkCount: removedHunks,
  removedChangedLineCount: removedChangedLines.length,
  removedSecurityCodeLines: 0,
  removedTestCodeLines: 0,
  retainedSectionsByteIdentical: true,
  sourceManifestSha256: sha256(manifestPath),
};

if (output) writeFileSync(resolve(output), `${JSON.stringify(proof, null, 2)}\n`);
else process.stdout.write(`${JSON.stringify(proof)}\n`);

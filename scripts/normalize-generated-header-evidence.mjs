#!/usr/bin/env node
/** SPDX-License-Identifier: Apache-2.0 */
import { createHash } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

const [rawRootArg, normalizedRootArg, reportArg] = process.argv.slice(2);
if (!rawRootArg || !normalizedRootArg || !reportArg || process.argv.length !== 5) {
  console.error("usage: normalize-generated-header-evidence.mjs <raw-root> <normalized-root> <report.json>");
  process.exit(64);
}

const rawRoot = resolve(rawRootArg);
const normalizedRoot = resolve(normalizedRootArg);
const reportPath = resolve(reportArg);
const runNames = ["baseline", "patched", "repeat", "repeat-2"];
const patchedRuns = ["patched", "repeat", "repeat-2"];
const manifestName = "SHA256SUMS";
const configDataPathPattern = /^archs\/[^/]+\/[^/]+\/configdata\.pm$/;
const ranlibPattern = /"RANLIB" => "CODE\(0x[0-9A-Fa-f]+\)"/g;
const ranlibReplacement = '"RANLIB" => "CODE(0x000000000000)"';
const fail = (message) => {
  throw new Error(`GENERATED_HEADER_EVIDENCE_ERROR=${message}`);
};
const sha256 = (buffer) => createHash("sha256").update(buffer).digest("hex");
const toPosix = (path) => path.split(sep).join("/");
const byteSort = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));

function isWithin(candidate, parent) {
  const path = relative(parent, candidate);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path));
}

if (isWithin(normalizedRoot, rawRoot) || isWithin(rawRoot, normalizedRoot)) {
  fail("normalized evidence path must not overlap raw evidence");
}
if (isWithin(reportPath, rawRoot)) {
  fail("reproducibility report must not be written inside raw evidence");
}
if (isWithin(reportPath, normalizedRoot)) {
  fail("reproducibility report must not be written inside normalized evidence");
}

function listFiles(root) {
  const output = [];
  const visit = (dir) => {
    for (const name of readdirSync(dir).sort(byteSort)) {
      const absolute = join(dir, name);
      const stat = lstatSync(absolute);
      if (stat.isSymbolicLink()) fail(`symlink is forbidden in evidence tree: ${toPosix(relative(root, absolute))}`);
      if (stat.isDirectory()) {
        visit(absolute);
      } else if (stat.isFile()) {
        const path = toPosix(relative(root, absolute));
        if (path !== manifestName) output.push(path);
      } else {
        fail(`non-regular evidence entry: ${toPosix(relative(root, absolute))}`);
      }
    }
  };
  visit(root);
  return output.sort(byteSort);
}

function canonicalManifest(root, paths) {
  return paths.map((path) => `${sha256(readFileSync(join(root, path)))}  ./${path}\n`).join("");
}

function verifyRawManifest(run, root, paths) {
  const manifestPath = join(root, manifestName);
  const actual = readFileSync(manifestPath, "utf8");
  const expected = canonicalManifest(root, paths);
  if (actual !== expected) fail(`raw SHA256SUMS does not cover the exact ${run} evidence tree`);
  return sha256(Buffer.from(actual));
}

function assertSameFileSet(fileSets) {
  const reference = JSON.stringify(fileSets[runNames[0]]);
  for (const run of runNames.slice(1)) {
    if (JSON.stringify(fileSets[run]) !== reference) {
      fail(`generated file set differs between ${runNames[0]} and ${run}`);
    }
  }
}

function byteDiff(left, right) {
  const shared = Math.min(left.length, right.length);
  let differentByteCount = Math.abs(left.length - right.length);
  let firstDifferenceByteOffset = left.length === right.length ? null : shared;
  for (let index = 0; index < shared; index += 1) {
    if (left[index] !== right[index]) {
      differentByteCount += 1;
      if (firstDifferenceByteOffset === null) firstDifferenceByteOffset = index;
    }
  }
  return { differentByteCount, firstDifferenceByteOffset };
}

function readPatchedBuffers(path) {
  return Object.fromEntries(
    patchedRuns.map((run) => [run, readFileSync(join(rawRoot, run, path))]),
  );
}

function rawFileRecord(path, buffers) {
  return {
    path,
    runs: Object.fromEntries(
      patchedRuns.map((run) => [run, { sha256: sha256(buffers[run]), size: buffers[run].length }]),
    ),
    pairwiseByteDiffs: {
      patched_vs_repeat: byteDiff(buffers.patched, buffers.repeat),
      patched_vs_repeat_2: byteDiff(buffers.patched, buffers["repeat-2"]),
      repeat_vs_repeat_2: byteDiff(buffers.repeat, buffers["repeat-2"]),
    },
  };
}

function normalizeExactlyOneRanlibPointer(run, path, sourceBuffer) {
  if (!configDataPathPattern.test(path)) {
    fail(`raw divergence is outside archs/<target>/<variant>/configdata.pm: ${path}`);
  }
  const text = sourceBuffer.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(sourceBuffer)) {
    fail(`configdata.pm is not canonical UTF-8: ${run}:${path}`);
  }
  const matches = [...text.matchAll(ranlibPattern)];
  if (matches.length !== 1) {
    fail(`expected exactly one RANLIB CODE pointer in divergent file: ${run}:${path}`);
  }
  return Buffer.from(text.replace(ranlibPattern, ranlibReplacement), "utf8");
}

for (const run of runNames) {
  const stat = lstatSync(join(rawRoot, run));
  if (!stat.isDirectory()) fail(`raw run directory is absent: ${run}`);
}

const fileSets = Object.fromEntries(runNames.map((run) => [run, listFiles(join(rawRoot, run))]));
assertSameFileSet(fileSets);
const rawManifestSha256 = Object.fromEntries(
  runNames.map((run) => [run, verifyRawManifest(run, join(rawRoot, run), fileSets[run])]),
);

const rawDivergentPaths = fileSets.patched.filter((path) => {
  const hashes = patchedRuns.map((run) => sha256(readFileSync(join(rawRoot, run, path))));
  return new Set(hashes).size !== 1;
});
const divergentPathSet = new Set(rawDivergentPaths);
const approvedDivergences = rawDivergentPaths.map((path) => {
  const buffers = readPatchedBuffers(path);
  const normalizedBuffers = Object.fromEntries(
    patchedRuns.map((run) => [run, normalizeExactlyOneRanlibPointer(run, path, buffers[run])]),
  );
  const normalizedHashes = patchedRuns.map((run) => sha256(normalizedBuffers[run]));
  if (new Set(normalizedHashes).size !== 1) {
    fail(`non-RANLIB content still diverges after normalization: ${path}`);
  }
  return {
    ...rawFileRecord(path, buffers),
    rule: "RANLIB_CODE_POINTER_ASLR_V1",
    replacementCountPerRun: 1,
    normalizedSha256: normalizedHashes[0],
  };
});

const baselinePointerPaths = fileSets.baseline.filter((path) => {
  const buffer = readFileSync(join(rawRoot, "baseline", path));
  return configDataPathPattern.test(path) && [...buffer.toString("utf8").matchAll(ranlibPattern)].length > 0;
});
if (JSON.stringify(baselinePointerPaths) !== JSON.stringify(rawDivergentPaths)) {
  fail("baseline RANLIB pointer paths do not exactly match patched raw divergences");
}

rmSync(normalizedRoot, { recursive: true, force: true });
for (const run of runNames) {
  const sourceRoot = join(rawRoot, run);
  const destinationRoot = join(normalizedRoot, run);
  for (const path of fileSets[run]) {
    const sourceBuffer = readFileSync(join(sourceRoot, path));
    const buffer = divergentPathSet.has(path)
      ? normalizeExactlyOneRanlibPointer(run, path, sourceBuffer)
      : sourceBuffer;
    const destination = join(destinationRoot, path);
    mkdirSync(dirname(destination), { recursive: true });
    writeFileSync(destination, buffer);
  }
  const normalizedPaths = listFiles(destinationRoot);
  if (JSON.stringify(normalizedPaths) !== JSON.stringify(fileSets[run])) {
    fail(`normalization changed the generated file set for ${run}`);
  }
  writeFileSync(join(destinationRoot, manifestName), canonicalManifest(destinationRoot, normalizedPaths));
}

for (const run of runNames) {
  const postNormalizationManifestSha256 = verifyRawManifest(run, join(rawRoot, run), fileSets[run]);
  if (postNormalizationManifestSha256 !== rawManifestSha256[run]) {
    fail(`normalization mutated raw generator evidence: ${run}`);
  }
}

const normalizedManifests = Object.fromEntries(
  patchedRuns.map((run) => [run, readFileSync(join(normalizedRoot, run, manifestName))]),
);
if (!normalizedManifests.patched.equals(normalizedManifests.repeat)
    || !normalizedManifests.repeat.equals(normalizedManifests["repeat-2"])
    || !normalizedManifests.patched.equals(normalizedManifests["repeat-2"])) {
  fail("normalized patched SHA256SUMS are not byte-identical");
}
const normalizedDifferences = fileSets.patched.filter((path) => {
  const hashes = patchedRuns.map((run) => sha256(readFileSync(join(normalizedRoot, run, path))));
  return new Set(hashes).size !== 1;
});
if (normalizedDifferences.length !== 0) {
  fail(`normalized patched trees still diverge: ${normalizedDifferences.join(",")}`);
}

const report = {
  schemaVersion: 1,
  policy: {
    id: "RANLIB_CODE_POINTER_ASLR_V1",
    scope: "evidence-copies-only",
    eligiblePathPattern: "^archs/<target>/<variant>/configdata.pm$",
    exactPattern: '"RANLIB" => "CODE(0x<hex>)"',
    replacement: ranlibReplacement,
    sourceGeneratorTreesMutated: false,
    rawEvidencePreserved: true,
    rawSha256CoverageVerified: true,
    normalizedSha256CoverageComplete: true,
    generatedDivergenceEnumerationExcludesDerivedEvidenceOnly: [manifestName],
  },
  runs: { baseline: "baseline", patched: patchedRuns },
  generatedFileCountPerRun: fileSets.patched.length,
  rawByteReproducible: rawDivergentPaths.length === 0,
  totalRawDivergentGeneratedFiles: rawDivergentPaths.length,
  rawDivergentGeneratedFiles: approvedDivergences,
  normalizedPatchedTreesByteIdentical: true,
  rawManifestSha256,
};
mkdirSync(dirname(reportPath), { recursive: true });
writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
writeFileSync(
  join(dirname(reportPath), "GENERATED_HEADER_RAW_DIVERGENT_FILES.txt"),
  rawDivergentPaths.length ? `${rawDivergentPaths.join("\n")}\n` : "",
);
process.stdout.write(`TOTAL_DIVERGENT_FILES=${rawDivergentPaths.length}\n`);
process.stdout.write("GENERATED_HEADER_EVIDENCE_NORMALIZATION=PASS\n");

#!/usr/bin/env node
/** SPDX-License-Identifier: Apache-2.0 */
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";

const [cacheDir, trivyVersion, output] = process.argv.slice(2);
if (!cacheDir || !trivyVersion || !output) throw new Error("usage: record-trivy-db.mjs CACHE_DIR TRIVY_VERSION OUTPUT");
function walk(path) {
  return readdirSync(path, { withFileTypes: true }).flatMap((entry) => {
    const child = join(path, entry.name);
    return entry.isDirectory() ? walk(child) : [child];
  });
}
function hash(path) { return createHash("sha256").update(readFileSync(path)).digest("hex"); }
if (!existsSync(cacheDir)) throw new Error("Trivy cache directory is absent");
const candidates = walk(cacheDir).filter((path) => path.endsWith("metadata.json"));
const database = candidates.map((path) => ({ path, metadata: JSON.parse(readFileSync(path, "utf8")) }))
  .find(({ metadata }) => metadata.UpdatedAt || metadata.NextUpdate || metadata.Version);
if (!database) throw new Error("Trivy database metadata is absent");
const result = {
  schemaVersion: 1,
  trivyVersion,
  metadataPath: relative(cacheDir, database.path),
  metadataSha256: hash(database.path),
  metadata: database.metadata,
};
writeFileSync(resolve(output), `${JSON.stringify(result, null, 2)}\n`);

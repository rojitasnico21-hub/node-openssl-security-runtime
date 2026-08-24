#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const [, , manifestArgument, key] = process.argv;

function fail(message) {
  console.error(message);
  process.exit(1);
}

if (!manifestArgument || !key) {
  fail("usage: read-manifest-value.mjs <manifest-path> <dotted-key>");
}

const manifestPath = resolve(manifestArgument);
let manifest;
try {
  manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
} catch (error) {
  fail(`unable to read manifest: ${manifestPath}: ${error.message}`);
}

let value = manifest;
for (const component of key.split(".")) {
  if (value === null || typeof value !== "object" || !(component in value)) {
    fail(`manifest key is missing: ${key}`);
  }
  value = value[component];
}

if ((typeof value !== "string" && typeof value !== "number") || String(value).length === 0) {
  fail(`manifest key is empty or has an unsupported type: ${key}`);
}

process.stdout.write(String(value));

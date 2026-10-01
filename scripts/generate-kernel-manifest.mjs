#!/usr/bin/env node
/**
 * M1-B6 — Offline manifest regeneration tool (maintainer/CI tooling ONLY).
 *
 * Regenerates kernel-manifest.json from the current tree. This is NEVER run
 * by the agent runtime: the runtime only verifies (read-only). Regeneration
 * is a deliberate, reviewed act that must land in the same commit as the
 * kernel-file change it reflects — CI fails if the manifest is stale.
 */

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const ROOT = process.cwd();
const MANIFEST_PATH = resolve(ROOT, "kernel-manifest.json");

// Must stay in lockstep with src/governance/kernel.ts KERNEL_FILES.
const KERNEL_FILES = [
  "constitution.md",
  "src/governance/kernel.ts",
  "src/agent/policy-engine.ts",
  "src/agent/policy-rules/authority.ts",
  "src/agent/policy-rules/command-safety.ts",
  "src/agent/policy-rules/financial.ts",
  "src/agent/policy-rules/index.ts",
  "src/agent/policy-rules/path-protection.ts",
  "src/agent/policy-rules/rate-limits.ts",
  "src/agent/policy-rules/validation.ts",
  "src/agent/injection-defense.ts",
  "src/net/policy.ts",
  "src/conway/http-client.ts",
  "src/agent/spend-tracker.ts",
  "src/conway/x402.ts",
  "src/conway/credits.ts",
  "src/identity/wallet.ts",
  "src/identity/chain.ts",
  "src/inference/provider-registry.ts",
  "src/self-mod/code.ts",
  "src/self-mod/upstream.ts",
  "src/self-mod/tools-manager.ts",
  "src/governance/promotion.ts",
].sort();

function normalize(content) {
  return Buffer.from(content.toString("utf8").replace(/\r\n/g, "\n").replace(/\r/g, "\n"), "utf8");
}

function sha256(content) {
  return createHash("sha256").update(normalize(content)).digest("hex");
}

const files = {};
for (const rel of KERNEL_FILES) {
  const absolute = join(ROOT, rel);
  try {
    files[rel] = sha256(readFileSync(absolute));
  } catch (error) {
    console.error(`Cannot read kernel file ${rel}: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }
}

writeFileSync(
  MANIFEST_PATH,
  `${JSON.stringify({ algorithm: "sha256", files }, null, 2)}\n`,
  "utf8",
);
console.log(`kernel-manifest.json regenerated (${KERNEL_FILES.length} files)`);

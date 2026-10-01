#!/usr/bin/env node
/**
 * M1-B6 — Fail-closed protected-kernel manifest verifier (CI + local).
 *
 * Mirrors src/governance/kernel.ts (same algorithm, same LF normalization,
 * same structural checks) but is intentionally dependency-free plain Node so
 * CI can run it BEFORE `pnpm install` — the kernel check cannot depend on
 * packages that themselves come from the supply chain being verified.
 *
 * Fails (exit 1) when:
 *  - the manifest is missing, unreadable, not JSON, structurally invalid,
 *    or empty;
 *  - any kernel file is missing;
 *  - any kernel file hash differs from the manifest (modified kernel file);
 *  - any file in src/governance/ is absent from the manifest (unexpected
 *    governance file — fail closed rather than silently ignore).
 *
 * Exit 0 only when every kernel file matches the committed manifest.
 */

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = process.cwd();
const MANIFEST_PATH = resolve(ROOT, "kernel-manifest.json");
const ALGORITHM = "sha256";

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
].sort();

function normalize(content) {
  return Buffer.from(content.toString("utf8").replace(/\r\n/g, "\n").replace(/\r/g, "\n"), "utf8");
}

function sha256(content) {
  return createHash(ALGORITHM).update(normalize(content)).digest("hex");
}

function fail(message) {
  console.error(`KERNEL MANIFEST CHECK FAILED: ${message}`);
  process.exit(1);
}

// ─── Load and structurally validate the manifest (fail closed) ──────

if (!existsSync(MANIFEST_PATH)) {
  fail(`kernel-manifest.json not found at repo root (${MANIFEST_PATH})`);
}

let parsed;
try {
  parsed = JSON.parse(readFileSync(MANIFEST_PATH, "utf8"));
} catch (error) {
  fail(`kernel-manifest.json is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
}

if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
  fail("kernel-manifest.json must be a JSON object");
}
if (parsed.algorithm !== ALGORITHM) {
  fail(`kernel-manifest.json algorithm must be "${ALGORITHM}"`);
}
if (!parsed.files || typeof parsed.files !== "object" || Array.isArray(parsed.files)) {
  fail("kernel-manifest.json files must be an object");
}

const files = parsed.files;
const entries = Object.entries(files);
if (entries.length === 0) {
  fail("kernel-manifest.json files object is empty");
}
for (const [key, value] of entries) {
  if (typeof key !== "string" || key.length === 0 || key.includes("..")) {
    fail(`kernel-manifest.json contains invalid path entry: ${String(key)}`);
  }
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    fail(`kernel-manifest.json entry for ${key} is not a sha256 hex digest`);
  }
}

// ─── Coverage: manifest must name exactly the kernel file set ────────

const manifestKeys = new Set(Object.keys(files));
for (const rel of KERNEL_FILES) {
  if (!manifestKeys.has(rel)) {
    fail(`kernel file missing from manifest: ${rel}`);
  }
}
for (const key of manifestKeys) {
  if (!KERNEL_FILES.includes(key)) {
    fail(`manifest names a file outside the kernel set: ${key}`);
  }
}

// ─── Hash verification ───────────────────────────────────────────────

const problems = [];
for (const rel of KERNEL_FILES) {
  const absolute = join(ROOT, rel);
  if (!existsSync(absolute)) {
    problems.push(`missing kernel file: ${rel}`);
    continue;
  }
  const actual = sha256(readFileSync(absolute));
  if (actual !== files[rel]) {
    problems.push(`hash mismatch: ${rel}`);
  }
}

// Extra hardening: every file in src/governance/ must be manifest-covered.
const governanceDir = join(ROOT, "src", "governance");
if (existsSync(governanceDir)) {
  for (const entry of readdirSync(governanceDir, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const rel = `src/governance/${entry.name}`;
    if (!manifestKeys.has(rel)) {
      problems.push(`unexpected governance file not covered by manifest: ${rel}`);
    }
  }
}

if (problems.length > 0) {
  console.error("KERNEL INTEGRITY PROBLEMS:");
  for (const problem of problems) console.error(`  - ${problem}`);
  console.error(
    "\nProtected-kernel files must match kernel-manifest.json exactly.",
    "Regenerate the manifest deliberately (node scripts/generate-kernel-manifest.mjs)",
    "in the same reviewed commit that changes a kernel file.",
  );
  process.exit(1);
}

console.log(`kernel manifest OK: ${KERNEL_FILES.length} protected files verified`);

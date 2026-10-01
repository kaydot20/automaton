/**
 * Protected Kernel (M1-B6, preflight §10)
 *
 * Hashed manifest of the security-critical kernel files, verified at boot and
 * in CI. Enforcement lives OUTSIDE every model-reachable path:
 *
 * - The manifest is generated deterministically (sorted paths, LF-normalized
 *   content) and committed. Nothing at runtime regenerates or rewrites it;
 *   `generateManifest` exists for CI/review tooling only and is never called
 *   from boot or tool paths.
 * - Boot verification refuses to start autonomous execution when the manifest
 *   itself is unusable (missing/invalid) and degrades to monitoring-only mode
 *   when kernel files no longer match their recorded hashes.
 * - While degraded, the kernel policy rule denies all financial, spawn, and
 *   self-modification tools (see policy-rules/kernel.ts).
 *
 * Manifest format (kernel-manifest.json, repo root):
 *   { "algorithm": "sha256", "files": { "<path>": "<hex digest>", ... } }
 *
 * Digests are computed over LF-normalized file content (CRLF/CR collapsed to
 * LF) so verification is byte-stable across checkouts with different
 * autocrlf settings. Paths are repo-relative POSIX paths, sorted.
 */

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const KERNEL_MANIFEST_FILENAME = "kernel-manifest.json";

/**
 * Kernel file set per preflight §10. Repo-relative POSIX paths, sorted at
 * manifest-build time. Adding a file here is a reviewed, CI-checked change:
 * the committed manifest must be regenerated in the same commit or CI fails.
 */
export const KERNEL_FILES: readonly string[] = Object.freeze([
  // Governance / constitution
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
  // Trust boundary
  "src/agent/injection-defense.ts",
  "src/net/policy.ts",
  "src/conway/http-client.ts",
  // Financial authority
  "src/agent/spend-tracker.ts",
  "src/conway/x402.ts",
  "src/conway/credits.ts",
  // Signer / payment authority
  "src/identity/wallet.ts",
  "src/identity/chain.ts",
  // Emergency-stop logic
  "src/inference/provider-registry.ts",
  // Capability elevation + self-update promotion substrate
  "src/self-mod/code.ts",
  "src/self-mod/upstream.ts",
  "src/self-mod/tools-manager.ts",
  "src/governance/promotion.ts",
]);

const MANIFEST_ALGORITHM = "sha256" as const;

export interface KernelManifest {
  algorithm: typeof MANIFEST_ALGORITHM;
  files: Record<string, string>;
}

export interface KernelFileEntry {
  path: string;
  exists: boolean;
  hash: string | null;
}

export type KernelVerdict =
  | { status: "ok"; manifestPath: string; checked: number }
  | { status: "degraded"; manifestPath: string; mismatches: string[]; missing: string[]; checked: number }
  | { status: "refuse"; manifestPath: string; reason: string };

export interface KernelBootCheck {
  verdict: KernelVerdict;
  /** True when the policy layer must deny financial/spawn/self-mod tools. */
  degraded: boolean;
  /** True when autonomous execution must not start at all. */
  mustRefuse: boolean;
}

/** Resolve the repo root that owns a given manifest location. */
export function resolveKernelRoot(manifestPath: string): string {
  return path.resolve(path.dirname(manifestPath));
}

/** Normalize EOLs so Windows checkouts hash identically to CI checkouts. */
function normalizeContent(content: Buffer): Buffer {
  return Buffer.from(content.toString("utf8").replace(/\r\n/g, "\n").replace(/\r/g, "\n"), "utf8");
}

function hashContent(content: Buffer): string {
  return createHash(MANIFEST_ALGORITHM).update(normalizeContent(content)).digest("hex");
}

/** Compute the deterministic kernel manifest from the files on disk. */
export function generateManifest(rootDir: string): KernelManifest {
  const root = path.resolve(rootDir);
  const files: Record<string, string> = {};

  for (const rel of [...KERNEL_FILES].sort()) {
    const absolute = path.join(root, rel);
    if (!fs.existsSync(absolute)) {
      throw new Error(`Kernel file missing while generating manifest: ${rel}`);
    }
    files[rel] = hashContent(fs.readFileSync(absolute));
  }

  return { algorithm: MANIFEST_ALGORITHM, files };
}

/** Serialize a manifest deterministically (sorted keys, LF endings). */
export function serializeManifest(manifest: KernelManifest): string {
  return `${JSON.stringify({ algorithm: manifest.algorithm, files: sortManifestFiles(manifest.files) }, null, 2)}\n`;
}

function sortManifestFiles(files: Record<string, string>): Record<string, string> {
  const sorted: Record<string, string> = {};
  for (const key of Object.keys(files).sort()) {
    sorted[key] = files[key];
  }
  return sorted;
}

/**
 * Load and structurally validate the manifest. Returns an error reason
 * instead of throwing — callers must fail closed on unusable manifests.
 */
export function loadManifest(manifestPath: string): { manifest: KernelManifest } | { error: string } {
  let raw: string;
  try {
    raw = fs.readFileSync(manifestPath, "utf8");
  } catch (error) {
    return { error: `kernel manifest unreadable: ${error instanceof Error ? error.message : String(error)}` };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    return { error: `kernel manifest is not valid JSON: ${error instanceof Error ? error.message : String(error)}` };
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { error: "kernel manifest must be a JSON object" };
  }

  const record = parsed as { algorithm?: unknown; files?: unknown };
  if (record.algorithm !== MANIFEST_ALGORITHM) {
    return { error: `kernel manifest algorithm must be "${MANIFEST_ALGORITHM}"` };
  }

  if (!record.files || typeof record.files !== "object" || Array.isArray(record.files)) {
    return { error: "kernel manifest files must be an object" };
  }

  const files: Record<string, string> = {};
  for (const [key, value] of Object.entries(record.files as Record<string, unknown>)) {
    if (typeof key !== "string" || key.length === 0 || key.includes("..") || path.isAbsolute(key)) {
      return { error: `kernel manifest contains invalid path entry: ${String(key)}` };
    }
    if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
      return { error: `kernel manifest entry for ${key} is not a sha256 hex digest` };
    }
    files[key] = value;
  }

  if (Object.keys(files).length === 0) {
    return { error: "kernel manifest files object is empty" };
  }

  return { manifest: { algorithm: MANIFEST_ALGORITHM, files } };
}

/** Hash every kernel file present on disk (missing files reported, not thrown). */
export function hashKernelFiles(rootDir: string): Map<string, KernelFileEntry> {
  const root = path.resolve(rootDir);
  const entries = new Map<string, KernelFileEntry>();

  for (const rel of KERNEL_FILES) {
    const absolute = path.join(root, rel);
    if (!fs.existsSync(absolute)) {
      entries.set(rel, { path: rel, exists: false, hash: null });
      continue;
    }
    entries.set(rel, { path: rel, exists: true, hash: hashContent(fs.readFileSync(absolute)) });
  }

  return entries;
}

/**
 * Verify kernel files against the manifest and produce the boot verdict.
 * Never throws for expected conditions; every failure mode lands in a typed
 * verdict so the boot path and tests can assert on them.
 */
export function verifyKernel(rootDir: string, manifestPath: string): KernelBootCheck {
  const loaded = loadManifest(manifestPath);
  if ("error" in loaded) {
    return {
      verdict: { status: "refuse", manifestPath, reason: loaded.error },
      degraded: true,
      mustRefuse: true,
    };
  }

  const manifest = loaded.manifest;
  const hashes = hashKernelFiles(rootDir);
  const mismatches: string[] = [];
  const missing: string[] = [];

  // 1) Every manifest entry must match disk.
  for (const [rel, expected] of Object.entries(manifest.files)) {
    const entry = hashes.get(rel);
    if (!entry) {
      mismatches.push(rel);
      continue;
    }
    if (!entry.exists || entry.hash === null) {
      missing.push(rel);
      continue;
    }
    if (entry.hash !== expected) {
      mismatches.push(rel);
    }
  }

  // 2) A kernel file on disk that is absent from the manifest is also a
  //    mismatch (unexpected kernel file — e.g. someone shadowing a module).
  for (const rel of KERNEL_FILES) {
    if (!(rel in manifest.files)) {
      mismatches.push(rel);
    }
  }

  if (missing.length > 0 || mismatches.length > 0) {
    return {
      verdict: { status: "degraded", manifestPath, mismatches, missing, checked: Object.keys(manifest.files).length },
      degraded: true,
      mustRefuse: false,
    };
  }

  return {
    verdict: { status: "ok", manifestPath, checked: Object.keys(manifest.files).length },
    degraded: false,
    mustRefuse: false,
  };
}

/** Default manifest location: repo root, next to package.json. */
export function defaultManifestPath(startDir = process.cwd()): string {
  return path.resolve(startDir, KERNEL_MANIFEST_FILENAME);
}

// ─── Escalation record (kv-persisted, survives restart) ──────────────

export const KERNEL_ESCALATION_KEY = "kernel_integrity_escalation";

export interface KernelEscalation {
  verdict: Exclude<KernelVerdict["status"], "ok">;
  reason: string;
  mismatches: string[];
  missing: string[];
  at: string;
}

/**
 * Persist an escalation record when integrity verification fails.
 * Uses the same kv store the runtime already relies on; written BEFORE any
 * degraded operation proceeds so the event survives restart.
 */
export function recordKernelEscalation(
  setKV: (key: string, value: string) => void,
  getKV: (key: string) => string | undefined,
  escalation: Omit<KernelEscalation, "at">,
): KernelEscalation {
  const record: KernelEscalation = { ...escalation, at: new Date().toISOString() };
  try {
    const existing = getKV(KERNEL_ESCALATION_KEY);
    const parsed: unknown = existing ? JSON.parse(existing) : null;
    if (
      parsed && typeof parsed === "object" && !Array.isArray(parsed) &&
      (parsed as KernelEscalation).verdict === record.verdict &&
      (parsed as KernelEscalation).reason === record.reason
    ) {
      return parsed as KernelEscalation; // already recorded — do not spam the audit trail
    }
  } catch {
    // fall through and overwrite with a fresh record
  }
  setKV(KERNEL_ESCALATION_KEY, JSON.stringify(record));
  return record;
}

export function readKernelEscalation(getKV: (key: string) => string | undefined): KernelEscalation | null {
  try {
    const raw = getKV(KERNEL_ESCALATION_KEY);
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed) && typeof (parsed as KernelEscalation).verdict === "string") {
      return parsed as KernelEscalation;
    }
    return null;
  } catch {
    return null;
  }
}

// ─── Degraded-mode state for the policy layer ────────────────────────

/**
 * Process-wide degraded-mode flag. Set once at boot (before any agent turn),
 * read synchronously by the kernel policy rule on every tool call.
 * It is intentionally NOT model-writable: no tool can clear it, and it can
 * only move from false -> true while the process runs.
 */
let kernelDegraded = false;

export function setKernelDegraded(value: boolean): void {
  kernelDegraded = value;
}

export function isKernelDegraded(): boolean {
  return kernelDegraded;
}

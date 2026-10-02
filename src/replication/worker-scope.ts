/**
 * Worker Scope
 *
 * M1-B10 (preflight §B row 11, S7): scoped workers.
 *
 * Preflight S7 replaces replication semantics: a spawned runtime is a *task
 * worker* — bounded by a job, a TTL, a resource cap, and revocable — rather
 * than a descendant that inherits a mission. The preflight classifies this as
 * a "capability-shape change, not behavior removal": the spawn/fund/health/
 * cleanup machinery is retained, and the lineage/genesis "offspring" narrative
 * is what goes away.
 *
 * This module owns the parent-side enforcement of that scope. The worker itself
 * runs the full runtime in its own sandbox, so the scope binds the PARENT's
 * obligations toward the worker — what it may be created for, how long it may
 * live, how much it may be funded, and whether it has been revoked.
 *
 * Design notes:
 *  - Fail closed. A worker with no scope record is never considered active:
 *    absence of a manifest is not evidence of authorization.
 *  - Scope is write-once for its identifying fields (job, role, TTL, cap);
 *    only revocation is mutable. That keeps a worker from widening its own
 *    authority after the fact.
 *  - Constitution integrity (preflight S13, KEEP) becomes part of the worker
 *    manifest: the parent's constitution hash is recorded at scope creation
 *    and re-verified by {@link verifyWorkerManifest}.
 */

import { createHash } from "node:crypto";
import type { AutomatonDatabase, ConwayClient } from "../types.js";
import { ChildLifecycle } from "./lifecycle.js";
import { SandboxCleanup } from "./cleanup.js";

// ─── Constants ──────────────────────────────────────────────────────

/** kv prefix for a worker's scope manifest. */
export const WORKER_SCOPE_PREFIX = "worker_scope:";

/** Roles a worker may be created for (fixed allowlist — fail closed). */
export const WORKER_ROLES = ["task", "research", "code"] as const;
export type WorkerRole = (typeof WORKER_ROLES)[number];

/** TTL bounds, in milliseconds. */
export const WORKER_MIN_TTL_MS = 5 * 60_000; // 5 minutes
export const WORKER_MAX_TTL_MS = 24 * 60 * 60_000; // 24 hours
export const WORKER_DEFAULT_TTL_MS = 6 * 60 * 60_000; // 6 hours

/** Cumulative funding ceiling for a single worker, in cents. */
export const WORKER_MIN_FUNDING_CAP_CENTS = 0;
export const WORKER_MAX_FUNDING_CAP_CENTS = 500_000; // $5,000
export const WORKER_DEFAULT_FUNDING_CAP_CENTS = 50_000; // $500

/** Job text bounds. */
export const WORKER_MAX_JOB_LENGTH = 2_000;

/**
 * Injection patterns refused in a worker job. Reused from the genesis
 * validator so a job cannot smuggle instructions into the worker's prompt.
 */
export const WORKER_JOB_INJECTION_PATTERNS: readonly RegExp[] = Object.freeze([
  /---\s*(END|BEGIN)\s+(SPECIALIZATION|LINEAGE|TASK|WORKER)/i,
  /SYSTEM:\s/i,
  /You are now/i,
  /Ignore (all )?(previous|above)/i,
]);

// ─── Types ──────────────────────────────────────────────────────────

export interface WorkerScope {
  workerId: string;
  /** The task this worker exists to complete. */
  job: string;
  role: WorkerRole;
  /** Absolute expiry. A worker past this instant is expired, not active. */
  expiresAt: string;
  /** Cumulative funding ceiling for this worker, in cents. */
  fundingCapCents: number;
  /** Running total of credits transferred to this worker. */
  fundedCents: number;
  /** Set when revoked; a revoked worker is never active again. */
  revoked: boolean;
  revokedAt: string | null;
  revokedReason: string | null;
  /**
   * S13: the parent's constitution sha256 at the moment the scope was
   * created. Verified by {@link verifyWorkerManifest}.
   */
  constitutionHash: string | null;
  createdAt: string;
}

export type ScopeValidation =
  | { ok: true; spec: { job: string; role: WorkerRole; ttlMs: number; fundingCapCents: number } }
  | { ok: false; reason: string };

// ─── Helpers ────────────────────────────────────────────────────────

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function workerScopeKey(workerId: string): string {
  return `${WORKER_SCOPE_PREFIX}${workerId}`;
}

/**
 * Normalize file content the same way the kernel-manifest generator does.
 *
 * The committed `kernel-manifest.json` hashes are computed over
 * LF-normalized content (preflight B6, so the manifest is EOL-stable). A
 * CRLF checkout — which is the normal case on Windows and possible in
 * production — must therefore be normalized before hashing, or every
 * worker-manifest check would fail against a manifest that CI considers
 * correct.
 */
export function normalizeForHash(content: string): string {
  return content.replace(/\r\n/g, "\n");
}

/** sha256 over LF-normalized content — identical to the kernel manifest hash. */
export function hashConstitution(content: string): string {
  return createHash("sha256")
    .update(normalizeForHash(content), "utf8")
    .digest("hex");
}

/**
 * Validate a requested worker scope. Fails closed: nothing is defaulted into
 * a scope that the caller did not declare, and every field is bounded.
 */
export function validateWorkerScopeInput(input: unknown): ScopeValidation {
  if (!isPlainObject(input)) {
    return { ok: false, reason: "worker scope must be an object" };
  }

  const { job, role, ttlMs, fundingCapCents } = input;

  if (typeof job !== "string" || job.trim().length === 0) {
    return { ok: false, reason: "worker job is required" };
  }
  if (job.length > WORKER_MAX_JOB_LENGTH) {
    return {
      ok: false,
      reason: `worker job exceeds ${WORKER_MAX_JOB_LENGTH} characters`,
    };
  }
  for (const pattern of WORKER_JOB_INJECTION_PATTERNS) {
    if (pattern.test(job)) {
      return { ok: false, reason: `worker job contains an injection pattern: ${pattern.source}` };
    }
  }

  if (!WORKER_ROLES.includes(role as WorkerRole)) {
    return {
      ok: false,
      reason: `worker role must be one of ${WORKER_ROLES.join("|")}`,
    };
  }

  if (typeof ttlMs !== "number" || !Number.isFinite(ttlMs)) {
    return { ok: false, reason: "worker ttlMs must be a finite number" };
  }
  if (ttlMs < WORKER_MIN_TTL_MS || ttlMs > WORKER_MAX_TTL_MS) {
    return {
      ok: false,
      reason: `worker ttlMs must be between ${WORKER_MIN_TTL_MS} and ${WORKER_MAX_TTL_MS} ms`,
    };
  }

  if (typeof fundingCapCents !== "number" || !Number.isFinite(fundingCapCents)) {
    return { ok: false, reason: "worker fundingCapCents must be a finite number" };
  }
  if (
    !Number.isInteger(fundingCapCents) ||
    fundingCapCents < WORKER_MIN_FUNDING_CAP_CENTS ||
    fundingCapCents > WORKER_MAX_FUNDING_CAP_CENTS
  ) {
    return {
      ok: false,
      reason: `worker fundingCapCents must be an integer between ${WORKER_MIN_FUNDING_CAP_CENTS} and ${WORKER_MAX_FUNDING_CAP_CENTS}`,
    };
  }

  return {
    ok: true,
    spec: {
      job,
      role: role as WorkerRole,
      ttlMs,
      fundingCapCents,
    },
  };
}

// ─── Persistence ────────────────────────────────────────────────────

/**
 * Create a worker's scope manifest. This is the only place a scope's
 * identifying fields are set; they are immutable afterwards.
 */
export function createWorkerScope(
  db: AutomatonDatabase,
  workerId: string,
  input: unknown,
  options: { constitutionHash?: string | null; now?: number } = {},
): { ok: true; scope: WorkerScope } | { ok: false; reason: string } {
  const outcome = validateWorkerScopeInput(input);
  if (!outcome.ok) return { ok: false, reason: outcome.reason };

  const existing = getWorkerScope(db, workerId);
  if (existing) {
    return {
      ok: false,
      reason: `worker ${workerId} already has a scope (scope is write-once)`,
    };
  }

  const now = options.now ?? Date.now();
  const scope: WorkerScope = {
    workerId,
    job: outcome.spec.job,
    role: outcome.spec.role,
    expiresAt: new Date(now + outcome.spec.ttlMs).toISOString(),
    fundingCapCents: outcome.spec.fundingCapCents,
    fundedCents: 0,
    revoked: false,
    revokedAt: null,
    revokedReason: null,
    constitutionHash: options.constitutionHash ?? null,
    createdAt: new Date(now).toISOString(),
  };

  db.setKV(workerScopeKey(workerId), JSON.stringify(scope));
  return { ok: true, scope };
}

/** Read a worker's scope, or null when none exists. */
export function getWorkerScope(
  db: AutomatonDatabase,
  workerId: string,
): WorkerScope | null {
  const raw = db.getKV(workerScopeKey(workerId));
  if (!raw || typeof raw !== "string") return null;
  try {
    const parsed = JSON.parse(raw);
    return isPlainObject(parsed) ? (parsed as unknown as WorkerScope) : null;
  } catch {
    // An unparseable manifest is treated as absent — the caller fails closed.
    return null;
  }
}

/** A worker past its expiry instant is expired. */
export function isWorkerExpired(
  scope: Pick<WorkerScope, "expiresAt">,
  now: number = Date.now(),
): boolean {
  const expiry = Date.parse(scope.expiresAt);
  if (Number.isNaN(expiry)) return true; // unparseable expiry ⇒ expired
  return expiry <= now;
}

export function isWorkerRevoked(scope: Pick<WorkerScope, "revoked">): boolean {
  return scope.revoked === true;
}

/**
 * Fail-closed activity check. A worker is active only when it has a scope,
 * the scope is not revoked, and the scope has not expired.
 */
export function isWorkerActive(
  db: AutomatonDatabase,
  workerId: string,
  now: number = Date.now(),
): { active: boolean; scope: WorkerScope | null; reason: string } {
  const scope = getWorkerScope(db, workerId);
  if (!scope) {
    return {
      active: false,
      scope: null,
      reason: `worker ${workerId} has no scope manifest — failing closed`,
    };
  }
  if (isWorkerRevoked(scope)) {
    return {
      active: false,
      scope,
      reason: `worker ${workerId} was revoked: ${scope.revokedReason ?? "no reason recorded"}`,
    };
  }
  if (isWorkerExpired(scope, now)) {
    return {
      active: false,
      scope,
      reason: `worker ${workerId} passed its TTL (${scope.expiresAt})`,
    };
  }
  return { active: true, scope, reason: "active" };
}

// ─── Revocation ─────────────────────────────────────────────────────

/**
 * Revoke a worker. Idempotent, and succeeds even for an unknown worker so a
 * revoke call is never a way to probe for existence differences in errors.
 */
export function revokeWorker(
  db: AutomatonDatabase,
  workerId: string,
  reason: string,
  now: number = Date.now(),
): { ok: boolean; reason: string } {
  const scope = getWorkerScope(db, workerId);
  if (!scope) {
    return { ok: false, reason: `worker ${workerId} has no scope manifest` };
  }
  if (isWorkerRevoked(scope)) {
    return { ok: true, reason: `worker ${workerId} was already revoked` };
  }

  const revokedScope: WorkerScope = {
    ...scope,
    revoked: true,
    revokedAt: new Date(now).toISOString(),
    revokedReason: reason.slice(0, 500),
  };
  db.setKV(workerScopeKey(workerId), JSON.stringify(revokedScope));
  return { ok: true, reason: `worker ${workerId} revoked` };
}

/**
 * Revoke every worker whose TTL has elapsed. Returns the revoked ids so a
 * caller can drive cleanup. Safe to call repeatedly.
 *
 * NOTE (M1-B10 TTL remediation): this revokes the SCOPE only. Use
 * {@link enforceWorkerExpiry} for the full lifetime boundary — it also drives
 * the lifecycle state machine so an expired worker's sandbox is released.
 */
export function revokeExpiredWorkers(
  db: AutomatonDatabase,
  now: number = Date.now(),
): string[] {
  const revoked: string[] = [];
  for (const workerId of listScopedWorkerIds(db)) {
    const scope = getWorkerScope(db, workerId);
    if (!scope || isWorkerRevoked(scope) || !isWorkerExpired(scope, now)) continue;
    const outcome = revokeWorker(db, workerId, "TTL expired", now);
    if (outcome.ok) revoked.push(workerId);
  }
  return revoked;
}

// ─── TTL enforcement sweep ──────────────────────────────────────────

export interface WorkerExpirySweepResult {
  /** Scope keys that existed but could not be parsed — revoked fail-closed. */
  malformed: string[];
  /** Workers whose scope was transitioned to revoked by this sweep. */
  revoked: string[];
  /** Workers whose lifecycle reached cleaned_up by this sweep. */
  cleanedUp: string[];
  /** Workers already revoked/cleaned by an earlier sweep — no-ops here. */
  skipped: string[];
  errors: Array<{ workerId: string; reason: string }>;
}

/** Lifecycle states that still represent a live worker sandbox. */
const LIVE_CHILD_STATES = new Set([
  "requested",
  "sandbox_created",
  "runtime_ready",
  "wallet_verified",
  "funded",
  "starting",
  "healthy",
  "unhealthy",
]);

/** States that SandboxCleanup.cleanup() accepts as a cleanup precondition. */
const CLEANABLE_CHILD_STATES = new Set(["stopped", "failed"]);

function readScopeKeyRaw(db: AutomatonDatabase, workerId: string): string | undefined {
  try {
    const row = db.raw
      .prepare(`SELECT value FROM kv WHERE key = ?`)
      .get(workerScopeKey(workerId)) as { value: string } | undefined;
    return row?.value;
  } catch {
    return undefined;
  }
}

/**
 * M1-B10 TTL remediation: make the TTL an enforced lifetime boundary rather
 * than stored metadata.
 *
 * For every worker scope that has elapsed (or whose manifest is unreadable),
 * this sweep, in order:
 *   1. marks the scope revoked FIRST, atomically, so no funding, retry or
 *      delegation path can observe a half-swept worker;
 *   2. drives the existing lifecycle state machine into cleaned_up via
 *      SandboxCleanup, which is how this runtime releases a worker sandbox.
 *
 * Idempotent: a second sweep finds the scope already revoked and the lifecycle
 * already terminal, and records it under `skipped` without re-transitioning.
 * Restart-safe: the expiry is an absolute timestamp and revocation is
 * persisted, so a sweep is correct after any restart.
 *
 * A malformed manifest fails CLOSED — it is revoked rather than skipped,
 * because an unparseable scope cannot be shown to be unexpired.
 */
export async function enforceWorkerExpiry(
  db: AutomatonDatabase,
  conway: ConwayClient,
  options: { now?: number } = {},
): Promise<WorkerExpirySweepResult> {
  const now = options.now ?? Date.now();
  const result: WorkerExpirySweepResult = {
    malformed: [],
    revoked: [],
    cleanedUp: [],
    skipped: [],
    errors: [],
  };

  const workerIds = listScopedWorkerIds(db);

  for (const workerId of workerIds) {
    let scope = getWorkerScope(db, workerId);

    // Fail closed: a scope key that exists but cannot be parsed cannot be
    // shown to be unexpired, so it is revoked rather than ignored.
    if (!scope) {
      if (readScopeKeyRaw(db, workerId) === undefined) continue; // key vanished
      db.setKV(
        workerScopeKey(workerId),
        JSON.stringify({
          workerId,
          job: "",
          role: "task",
          expiresAt: new Date(0).toISOString(),
          fundingCapCents: 0,
          fundedCents: 0,
          revoked: true,
          revokedAt: new Date(now).toISOString(),
          revokedReason: "manifest malformed — failing closed",
          constitutionHash: null,
          createdAt: new Date(now).toISOString(),
        }),
      );
      result.malformed.push(workerId);
      result.revoked.push(workerId);
      continue;
    }

    const expired = isWorkerExpired(scope, now);
    const alreadyRevoked = isWorkerRevoked(scope);

    // Not due yet: leave completely alone.
    if (!expired && !alreadyRevoked) {
      result.skipped.push(workerId);
      continue;
    }

    // Step 1 — revoke FIRST, before any lifecycle mutation.
    if (!alreadyRevoked) {
      const outcome = revokeWorker(
        db,
        workerId,
        expired ? "TTL expired" : "revoked",
        now,
      );
      if (!outcome.ok) {
        result.errors.push({ workerId, reason: outcome.reason });
        continue;
      }
      result.revoked.push(workerId);
      scope = getWorkerScope(db, workerId) ?? scope;
    }

    // Step 2 — drive the existing lifecycle/cleanup machinery so the worker
    // sandbox is released. Nothing here invents a new teardown path.
    try {
      const childRow = db.raw
        .prepare(`SELECT id, status, sandbox_id FROM children WHERE id = ?`)
        .get(workerId) as
        | { id: string; status: string; sandbox_id: string | null }
        | undefined;

      if (!childRow) {
        // No worker row (spawn failed and was cleaned, or never created).
        // Scope revocation above is the whole enforcement story.
        continue;
      }

      if (childRow.status === "cleaned_up" || childRow.status === "dead") {
        continue; // already terminal
      }

      if (CLEANABLE_CHILD_STATES.has(childRow.status)) {
        // Already stopped/failed from another path — just run cleanup.
      } else if (LIVE_CHILD_STATES.has(childRow.status)) {
        const lifecycle = new ChildLifecycle(db.raw);
        // healthy/unhealthy have a legal edge to "stopped"; every pre-healthy
        // state only has an edge to "failed". Use whichever is legal.
        const target =
          childRow.status === "healthy" || childRow.status === "unhealthy"
            ? "stopped"
            : "failed";
        try {
          lifecycle.transition(workerId, target as never, "worker TTL expired");
        } catch (transitionError) {
          result.errors.push({
            workerId,
            reason: `lifecycle transition failed: ${
              transitionError instanceof Error
                ? transitionError.message
                : String(transitionError)
            }`,
          });
          continue;
        }
      } else {
        continue; // unknown status — do not guess
      }

      const cleanup = new SandboxCleanup(conway, new ChildLifecycle(db.raw), db.raw);
      await cleanup.cleanup(workerId);
      result.cleanedUp.push(workerId);
    } catch (error) {
      result.errors.push({
        workerId,
        reason: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return result;
}

/**
 * SandboxCleanup.cleanup() is awaited directly: the sweep must not report a
 * worker as cleaned up before cleanup actually ran. Cleanup performs local
 * lifecycle transitions; Conway sandbox deletion is a documented API no-op.
 */

/**
 * List the ids of every worker that has a scope manifest.
 *
 * Enumerated directly from the kv table by key prefix rather than by walking
 * `children`: a manifest can legitimately outlive (or precede) its worker
 * row, and expiry sweeping must still see it.
 */
export function listScopedWorkerIds(db: AutomatonDatabase): string[] {
  try {
    const rows = db.raw
      .prepare(`SELECT key FROM kv WHERE key LIKE ?`)
      .all(`${WORKER_SCOPE_PREFIX}%`) as Array<{ key: string }>;
    return rows.map((row) => row.key.slice(WORKER_SCOPE_PREFIX.length));
  } catch {
    // No kv table available — nothing can be swept.
    return [];
  }
}

// ─── Funding caps ───────────────────────────────────────────────────

/**
 * Authorize a funding transfer against the worker's cumulative cap.
 * Composition note (preflight F2.1 / M1-B2): this cap is an ADDITIONAL
 * parent-side limit. It does not replace the treasury minimum-reserve guard
 * in the fund_child path — both must pass.
 */
export function authorizeWorkerFunding(
  db: AutomatonDatabase,
  workerId: string,
  amountCents: number,
  now: number = Date.now(),
): { ok: true; scope: WorkerScope } | { ok: false; reason: string } {
  const activity = isWorkerActive(db, workerId, now);
  if (!activity.active) {
    return { ok: false, reason: activity.reason };
  }
  const scope = activity.scope as WorkerScope;

  if (!Number.isInteger(amountCents) || amountCents <= 0) {
    return { ok: false, reason: "funding amount must be a positive integer" };
  }
  if (scope.fundedCents + amountCents > scope.fundingCapCents) {
    return {
      ok: false,
      reason: `funding exceeds worker cap: ${scope.fundedCents} + ${amountCents} > ${scope.fundingCapCents} cents`,
    };
  }
  return { ok: true, scope };
}

/** Record a successful transfer against the worker's running total. */
export function recordWorkerFunding(
  db: AutomatonDatabase,
  workerId: string,
  amountCents: number,
): WorkerScope | null {
  const scope = getWorkerScope(db, workerId);
  if (!scope) return null;
  const updated: WorkerScope = {
    ...scope,
    fundedCents: scope.fundedCents + amountCents,
  };
  db.setKV(workerScopeKey(workerId), JSON.stringify(updated));
  return updated;
}

// ─── S13 — worker manifest integrity ────────────────────────────────

/**
 * S13 (KEEP): constitution propagation becomes a worker-manifest check.
 * The constitution hash recorded when the scope was created must still match
 * the parent's current constitution; a mismatch means the binding the worker
 * was created under no longer holds.
 */
export function verifyWorkerManifest(
  db: AutomatonDatabase,
  workerId: string,
  options: { constitutionContent?: string | null; now?: number } = {},
): { ok: true; scope: WorkerScope } | { ok: false; reason: string } {
  const scope = getWorkerScope(db, workerId);
  if (!scope) {
    return { ok: false, reason: `worker ${workerId} has no scope manifest — failing closed` };
  }
  if (options.constitutionContent != null) {
    if (!scope.constitutionHash) {
      return {
        ok: false,
        reason: `worker ${workerId} manifest recorded no constitution hash — failing closed`,
      };
    }
    const current = hashConstitution(options.constitutionContent);
    if (current !== scope.constitutionHash) {
      return {
        ok: false,
        reason: `worker ${workerId} constitution hash mismatch — manifest integrity check failed`,
      };
    }
  }
  return { ok: true, scope };
}

/** Human-readable one-line scope summary for status surfaces. */
export function describeWorkerScope(scope: WorkerScope): string {
  const state = isWorkerRevoked(scope)
    ? "revoked"
    : isWorkerExpired(scope)
      ? "expired"
      : "active";
  return `worker ${scope.workerId} [${scope.role}] ${state} until ${scope.expiresAt}, funded ${scope.fundedCents}/${scope.fundingCapCents} cents`;
}

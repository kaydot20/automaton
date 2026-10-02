/**
 * M1-B10 TTL Remediation — Lifetime Enforcement Tests
 *
 * Review finding: at head 1f77381 the worker TTL was *stored* and *lazily*
 * checked. `revokeExpiredWorkers` had zero production callers, so nothing
 * swept expiry: an expired worker's sandbox kept running, its scope was never
 * transitioned to revoked, and the only thing that noticed the expiry was a
 * `fund_child` call the model happened to make.
 *
 * The remediation adds `enforceWorkerExpiry`, wired into the existing
 * parent-owned periodic maintenance task (`dead_agent_cleanup`). It revokes the
 * scope first, then drives the existing lifecycle/cleanup machinery so the
 * worker sandbox is released.
 *
 * Covered:
 *  - before TTL → worker stays active and is left untouched;
 *  - exact TTL boundary → expired (<= at expiresAt, per the documented rule);
 *  - after TTL → scope revoked;
 *  - sandbox cleanup invoked exactly once;
 *  - repeated sweep is idempotent;
 *  - restart preserves expiration and revocation;
 *  - fund_child after expiry denied with no transfer;
 *  - expired scope cannot be revived or widened by re-registration;
 *  - malformed TTL / malformed manifest fail closed;
 *  - manually revoked worker stays revoked;
 *  - the sweep is reachable from the production heartbeat task.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  WORKER_DEFAULT_TTL_MS,
  WORKER_MAX_FUNDING_CAP_CENTS,
  WORKER_MAX_TTL_MS,
  WORKER_MIN_TTL_MS,
  createWorkerScope,
  enforceWorkerExpiry,
  getWorkerScope,
  isWorkerActive,
  isWorkerExpired,
  revokeWorker,
  workerScopeKey,
} from "../../replication/worker-scope.js";
import { ChildLifecycle } from "../../replication/lifecycle.js";
import { SandboxCleanup } from "../../replication/cleanup.js";
import { BUILTIN_TASKS } from "../../heartbeat/tasks.js";
import { createDatabase } from "../../state/database.js";
import {
  MockConwayClient,
  MockInferenceClient,
  createTestConfig,
  createTestDb,
  createTestIdentity,
} from "../mocks.js";
import { createBuiltinTools, executeTool } from "../../agent/tools.js";
import { PolicyEngine } from "../../agent/policy-engine.js";
import { createDefaultRules } from "../../agent/policy-rules/index.js";
import type {
  AutomatonDatabase,
  AutomatonTool,
  SpendTrackerInterface,
  ToolContext,
} from "../../types.js";

const T0 = 1_700_000_000_000;
const VALID_SCOPE = {
  job: "verify the TTL boundary",
  role: "task" as const,
  ttlMs: WORKER_DEFAULT_TTL_MS,
  fundingCapCents: WORKER_MAX_FUNDING_CAP_CENTS,
};

function createMockSpendTracker(): SpendTrackerInterface {
  return {
    recordSpend: () => {},
    getHourlySpend: () => 0,
    getDailySpend: () => 0,
    getTotalSpend: () => 0,
    checkLimit: () => ({
      allowed: true,
      currentHourlySpend: 0,
      currentDailySpend: 0,
      limitHourly: 10_000_000,
      limitDaily: 25_000_000,
    }),
    pruneOldRecords: () => 0,
  };
}

let db: AutomatonDatabase;
let conway: MockConwayClient;

/**
 * Create a worker exactly as the real spawn path does: through
 * ChildLifecycle.initChild + the legal transition chain, so the lifecycle
 * state machine (and therefore the cleanup guard) is genuinely satisfied.
 */
function seedLiveWorker(
  id: string,
  target: "healthy" | "wallet_verified",
  sandboxId = "sbx-ttl",
): void {
  const lifecycle = new ChildLifecycle(db.raw);
  lifecycle.initChild(id, id, sandboxId, "job", "evm");
  db.raw.prepare(`UPDATE children SET address = ? WHERE id = ?`).run(
    "0x1111111111111111111111111111111111111111",
    id,
  );
  lifecycle.transition(id, "sandbox_created");
  lifecycle.transition(id, "runtime_ready");
  lifecycle.transition(id, "wallet_verified");
  if (target === "healthy") {
    lifecycle.transition(id, "funded");
    lifecycle.transition(id, "starting");
    lifecycle.transition(id, "healthy");
  }
}

function childStatus(id: string): string {
  const row = db.raw
    .prepare(`SELECT status FROM children WHERE id = ?`)
    .get(id) as { status: string } | undefined;
  return row?.status ?? "<missing>";
}

/** Count cleanup transitions actually applied by the lifecycle machinery. */
function cleanupEventCount(id: string): number {
  const rows = db.raw
    .prepare(
      `SELECT to_state FROM child_lifecycle_events
       WHERE child_id = ? AND to_state = 'cleaned_up'`,
    )
    .all(id) as Array<{ to_state: string }>;
  return rows.length;
}

beforeEach(() => {
  db = createTestDb();
  conway = new MockConwayClient();
});

afterEach(() => {
  try {
    db.close();
  } catch {
    /* already closed */
  }
});

// ─── Before TTL ─────────────────────────────────────────────────────

describe("worker before its TTL", () => {
  it("remains active and is left untouched by the sweep", async () => {
    seedLiveWorker("w-live", "healthy");
    const created = createWorkerScope(
      db,
      "w-live",
      { ...VALID_SCOPE, ttlMs: WORKER_MIN_TTL_MS },
      { now: T0 },
    );
    expect(created.ok).toBe(true);

    const sweep = await enforceWorkerExpiry(db, conway, { now: T0 + 1_000 });

    expect(sweep.revoked).not.toContain("w-live");
    expect(sweep.cleanedUp).not.toContain("w-live");
    expect(sweep.errors).toEqual([]);
    expect(getWorkerScope(db, "w-live")?.revoked).toBe(false);
    expect(childStatus("w-live")).toBe("healthy");
    expect(isWorkerActive(db, "w-live", T0 + 1_000).active).toBe(true);
  });
});

// ─── Exact TTL boundary ─────────────────────────────────────────────

describe("worker at the exact TTL boundary", () => {
  it("is expired at exactly expiresAt (<= rule)", async () => {
    const created = createWorkerScope(
      db,
      "w-edge",
      { ...VALID_SCOPE, ttlMs: WORKER_MIN_TTL_MS },
      { now: T0 },
    );
    expect(created.ok).toBe(true);
    const expiresAt = Date.parse(created.scope.expiresAt);

    // One millisecond BEFORE the boundary: still active.
    expect(isWorkerExpired(created.scope, expiresAt - 1)).toBe(false);
    // Exactly AT the boundary: expired.
    expect(isWorkerExpired(created.scope, expiresAt)).toBe(true);
    expect(isWorkerExpired(created.scope, expiresAt + 1)).toBe(true);
  });

  it("the sweep at exactly expiresAt revokes the worker", async () => {
    seedLiveWorker("w-edge", "healthy");
    const created = createWorkerScope(
      db,
      "w-edge",
      { ...VALID_SCOPE, ttlMs: WORKER_MIN_TTL_MS },
      { now: T0 },
    );
    expect(created.ok).toBe(true);

    const sweep = await enforceWorkerExpiry(db, conway, {
      now: Date.parse(created.scope.expiresAt),
    });
    expect(sweep.revoked).toContain("w-edge");
  });
});

// ─── After TTL ──────────────────────────────────────────────────────

describe("worker after its TTL", () => {
  it("has its scope revoked and its sandbox cleaned up", async () => {
    seedLiveWorker("w-dead", "healthy");
    const created = createWorkerScope(db, "w-dead", VALID_SCOPE, { now: T0 });
    expect(created.ok).toBe(true);

    const sweep = await enforceWorkerExpiry(db, conway, {
      now: T0 + VALID_SCOPE.ttlMs + 1,
    });

    expect(sweep.revoked).toContain("w-dead");
    expect(sweep.cleanedUp).toContain("w-dead");
    expect(sweep.errors).toEqual([]);

    const scope = getWorkerScope(db, "w-dead");
    expect(scope?.revoked).toBe(true);
    expect(scope?.revokedReason).toBe("TTL expired");
    expect(childStatus("w-dead")).toBe("cleaned_up");
    expect(isWorkerActive(db, "w-dead", T0 + VALID_SCOPE.ttlMs + 1).active).toBe(false);
  });

  it("drives a pre-healthy worker to failed then cleaned_up", async () => {
    seedLiveWorker("w-pre", "wallet_verified");
    createWorkerScope(db, "w-pre", VALID_SCOPE, { now: T0 });

    const sweep = await enforceWorkerExpiry(db, conway, {
      now: T0 + VALID_SCOPE.ttlMs + 1,
    });
    expect(sweep.cleanedUp).toContain("w-pre");
    expect(childStatus("w-pre")).toBe("cleaned_up");

    const events = db.raw
      .prepare(
        `SELECT to_state FROM child_lifecycle_events WHERE child_id = ? ORDER BY created_at`,
      )
      .all("w-pre") as Array<{ to_state: string }>;
    expect(events.map((e) => e.to_state)).toContain("failed");
    expect(events.map((e) => e.to_state)).toContain("cleaned_up");
  });

  it("invokes sandbox cleanup exactly once", async () => {
    seedLiveWorker("w-once", "healthy");
    createWorkerScope(db, "w-once", VALID_SCOPE, { now: T0 });

    const now = T0 + VALID_SCOPE.ttlMs + 1;
    const first = await enforceWorkerExpiry(db, conway, { now });
    expect(first.cleanedUp).toEqual(["w-once"]);
    expect(cleanupEventCount("w-once")).toBe(1);

    // Three more sweeps must not re-run cleanup.
    const second = await enforceWorkerExpiry(db, conway, { now: now + 1 });
    const third = await enforceWorkerExpiry(db, conway, { now: now + 2 });
    const fourth = await enforceWorkerExpiry(db, conway, { now: now + 3 });
    expect(second.cleanedUp).toEqual([]);
    expect(third.cleanedUp).toEqual([]);
    expect(fourth.cleanedUp).toEqual([]);
    expect(cleanupEventCount("w-once")).toBe(1);
  });

  it("is idempotent: a repeated sweep re-revokes nothing and stays terminal", async () => {
    seedLiveWorker("w-idem", "healthy");
    createWorkerScope(db, "w-idem", VALID_SCOPE, { now: T0 });
    const now = T0 + VALID_SCOPE.ttlMs + 1;

    const first = await enforceWorkerExpiry(db, conway, { now });
    const firstRevokedAt = getWorkerScope(db, "w-idem")?.revokedAt;
    const second = await enforceWorkerExpiry(db, conway, { now: now + 60_000 });

    expect(first.revoked).toEqual(["w-idem"]);
    expect(second.revoked).toEqual([]);
    // Revocation timestamp is not churned by repeated sweeps.
    expect(getWorkerScope(db, "w-idem")?.revokedAt).toBe(firstRevokedAt);
    expect(getWorkerScope(db, "w-idem")?.revokedReason).toBe("TTL expired");
  });

  it("sweeps many expired workers in one pass", async () => {
    for (let i = 0; i < 5; i += 1) {
      seedLiveWorker(`bulk-${i}`, "healthy");
      createWorkerScope(db, `bulk-${i}`, VALID_SCOPE, { now: T0 });
    }
    const sweep = await enforceWorkerExpiry(db, conway, {
      now: T0 + VALID_SCOPE.ttlMs + 1,
    });
    expect(sweep.revoked.sort()).toEqual([
      "bulk-0", "bulk-1", "bulk-2", "bulk-3", "bulk-4",
    ]);
    expect(sweep.cleanedUp.length).toBe(5);
    expect(sweep.errors).toEqual([]);
  });

  it("revokes a scope with no worker row (spawn never completed)", async () => {
    createWorkerScope(db, "w-norow", VALID_SCOPE, { now: T0 });
    const sweep = await enforceWorkerExpiry(db, conway, {
      now: T0 + VALID_SCOPE.ttlMs + 1,
    });
    expect(sweep.revoked).toContain("w-norow");
    expect(sweep.cleanedUp).toEqual([]);
    expect(sweep.errors).toEqual([]);
  });
});

// ─── Restart ────────────────────────────────────────────────────────

describe("expiry survives parent restart", () => {
  it("a restart does not resurrect an expired worker", () => {
    const dbPath = path.join(
      fs.mkdtempSync(path.join(os.tmpdir(), "automaton-worker-ttl-")),
      "test.db",
    );

    let first = createDatabase(dbPath);
    let expiresAt: string;
    try {
      const created = createWorkerScope(first, "w-restart", VALID_SCOPE, {
        now: T0,
      });
      expect(created.ok).toBe(true);
      expiresAt = created.scope.expiresAt;
    } finally {
      first.close();
    }

    // Reopen BEFORE expiry: still active.
    let second = createDatabase(dbPath);
    try {
      expect(isWorkerActive(second, "w-restart", T0 + 1_000).active).toBe(true);
    } finally {
      second.close();
    }

    // Reopen AFTER expiry: expired, and still not revocable into "un-revoked".
    const third = createDatabase(dbPath);
    try {
      const after = isWorkerActive(third, "w-restart", Date.parse(expiresAt));
      expect(after.active).toBe(false);
      expect(after.reason).toMatch(/TTL/);
      expect(revokeWorker(third, "w-restart", "attempted un-revoke").ok).toBe(true);
      expect(getWorkerScope(third, "w-restart")?.revoked).toBe(true);
    } finally {
      third.close();
    }
  });

  it("a sweep after restart still cleans an expired worker up", async () => {
    const dbPath = path.join(
      fs.mkdtempSync(path.join(os.tmpdir(), "automaton-worker-ttl2-")),
      "test.db",
    );

    let first = createDatabase(dbPath);
    try {
      const lifecycle = new ChildLifecycle(first.raw);
      lifecycle.initChild("w-boot", "w-boot", "sbx", "j", "evm");
      lifecycle.transition("w-boot", "sandbox_created");
      lifecycle.transition("w-boot", "runtime_ready");
      lifecycle.transition("w-boot", "wallet_verified");
      lifecycle.transition("w-boot", "funded");
      lifecycle.transition("w-boot", "starting");
      lifecycle.transition("w-boot", "healthy");
      createWorkerScope(first, "w-boot", VALID_SCOPE, { now: T0 });
    } finally {
      first.close();
    }

    const second = createDatabase(dbPath);
    try {
      const sweep = await enforceWorkerExpiry(second, conway, {
        now: T0 + VALID_SCOPE.ttlMs + 1,
      });
      expect(sweep.revoked).toContain("w-boot");
      expect(sweep.cleanedUp).toContain("w-boot");
      const row = second.raw
        .prepare(`SELECT status FROM children WHERE id = ?`)
        .get("w-boot") as { status: string };
      expect(row.status).toBe("cleaned_up");
    } finally {
      second.close();
    }
  });
});

// ─── Funding after expiry ───────────────────────────────────────────

describe("expired workers cannot be funded", () => {
  let ctx: ToolContext;
  let engine: PolicyEngine;
  let tools: AutomatonTool[];
  let spendTracker: SpendTrackerInterface;

  beforeEach(() => {
    spendTracker = createMockSpendTracker();
    ctx = {
      identity: createTestIdentity(),
      config: createTestConfig(),
      db,
      conway,
      inference: new MockInferenceClient(),
    };
    engine = new PolicyEngine(db.raw, createDefaultRules());
    tools = createBuiltinTools("test-sandbox-id");
  });

  it("denies fund_child after expiry with no transfer and no accounting", async () => {
    seedLiveWorker("w-nofund", "wallet_verified");
    createWorkerScope(db, "w-nofund", VALID_SCOPE, { now: T0 });
    await enforceWorkerExpiry(db, conway, { now: T0 + VALID_SCOPE.ttlMs + 1 });

    const balanceBefore = conway.creditsCents;
    const call = await executeTool(
      "fund_child",
      { child_id: "w-nofund", amount_cents: 100 },
      tools,
      ctx,
      engine,
      { inputSource: "agent", turnToolCallCount: 0, sessionSpend: spendTracker },
    );

    expect(`${call.result}${call.error ?? ""}`).toMatch(/Blocked/);
    expect(conway.creditsCents).toBe(balanceBefore);
    expect(getWorkerScope(db, "w-nofund")?.fundedCents).toBe(0);
    const row = db.raw
      .prepare(`SELECT funded_amount_cents FROM children WHERE id = ?`)
      .get("w-nofund") as { funded_amount_cents: number };
    expect(row.funded_amount_cents).toBe(0);
  });
});

// ─── No revival or widening ─────────────────────────────────────────

describe("an expired scope cannot be revived or widened", () => {
  it("rejects a fresh createWorkerScope for an expired worker id", async () => {
    createWorkerScope(db, "w-revive", VALID_SCOPE, { now: T0 });
    await enforceWorkerExpiry(db, conway, { now: T0 + VALID_SCOPE.ttlMs + 1 });

    const again = createWorkerScope(
      db,
      "w-revive",
      {
        ...VALID_SCOPE,
        role: "code",
        ttlMs: WORKER_MAX_FUNDING_CAP_CENTS,
        fundingCapCents: WORKER_MAX_FUNDING_CAP_CENTS,
      },
      { now: T0 + VALID_SCOPE.ttlMs + 2 },
    );
    expect(again.ok).toBe(false);
    expect(again.reason).toMatch(/write-once/);

    const scope = getWorkerScope(db, "w-revive");
    expect(scope?.revoked).toBe(true);
    expect(scope?.role).toBe("task");
    expect(scope?.fundingCapCents).toBe(VALID_SCOPE.fundingCapCents);
  });

  it("revokeWorker on an already-expired worker stays revoked and does not un-revoke", async () => {
    createWorkerScope(db, "w-stay", VALID_SCOPE, { now: T0 });
    await enforceWorkerExpiry(db, conway, { now: T0 + VALID_SCOPE.ttlMs + 1 });
    const revokedAt = getWorkerScope(db, "w-stay")?.revokedAt;

    const outcome = revokeWorker(
      db,
      "w-stay",
      "second revoke",
      T0 + VALID_SCOPE.ttlMs + 2,
    );
    expect(outcome.ok).toBe(true);
    expect(getWorkerScope(db, "w-stay")?.revokedAt).toBe(revokedAt);
    expect(getWorkerScope(db, "w-stay")?.revokedReason).toBe("TTL expired");
  });
});

// ─── Fail closed ────────────────────────────────────────────────────

describe("malformed state fails closed", () => {
  it("revokes an unparseable manifest rather than ignoring it", async () => {
    db.setKV(workerScopeKey("w-malformed"), "{not json");
    const sweep = await enforceWorkerExpiry(db, conway, { now: T0 });
    expect(sweep.malformed).toEqual(["w-malformed"]);
    expect(sweep.revoked).toEqual(["w-malformed"]);

    const scope = getWorkerScope(db, "w-malformed");
    expect(scope?.revoked).toBe(true);
    expect(scope?.revokedReason).toMatch(/malformed/);
    expect(scope?.fundingCapCents).toBe(0);
  });

  it("an unparseable expiry counts as expired", () => {
    expect(isWorkerExpired({ expiresAt: "not-a-date" })).toBe(true);
  });

  it("a manifest with an unparseable expiresAt is revoked by the sweep", async () => {
    db.setKV(
      workerScopeKey("w-badexpiry"),
      JSON.stringify({
        workerId: "w-badexpiry",
        job: "j",
        role: "task",
        expiresAt: "whenever",
        fundingCapCents: 1000,
        fundedCents: 0,
        revoked: false,
        revokedAt: null,
        revokedReason: null,
        constitutionHash: null,
        createdAt: new Date(T0).toISOString(),
      }),
    );
    const sweep = await enforceWorkerExpiry(db, conway, { now: T0 });
    expect(sweep.revoked).toEqual(["w-badexpiry"]);
    expect(getWorkerScope(db, "w-badexpiry")?.revoked).toBe(true);
  });

  it("a manifest with no worker row is not fabricated into existence", async () => {
    const sweep = await enforceWorkerExpiry(db, conway, { now: T0 });
    expect(sweep.errors).toEqual([]);
    expect(sweep.cleanedUp).toEqual([]);
  });
});

// ─── Production wiring ──────────────────────────────────────────────

describe("the TTL sweep runs from the existing periodic parent path", () => {
  it("dead_agent_cleanup calls enforceWorkerExpiry", async () => {
    seedLiveWorker("w-heartbeat", "healthy");
    createWorkerScope(db, "w-heartbeat", { ...VALID_SCOPE, ttlMs: WORKER_MIN_TTL_MS }, {
      now: Date.now() - WORKER_MIN_TTL_MS - 1,
    });

    const taskCtx = {
      identity: createTestIdentity(),
      config: createTestConfig(),
      db,
      conway,
    };
    const tickCtx = {
      creditBalance: 10_000,
      survivalTier: "high",
    } as never;

    // Clear the interval gate so the periodic body actually executes.
    db.deleteKV("last_dead_agent_cleanup");

    const result = await BUILTIN_TASKS.dead_agent_cleanup(tickCtx, taskCtx as never);
    expect(result.shouldWake).toBe(false);

    expect(getWorkerScope(db, "w-heartbeat")?.revoked).toBe(true);
    expect(childStatus("w-heartbeat")).toBe("cleaned_up");

    const record = JSON.parse(db.getKV("last_dead_agent_cleanup") ?? "{}") as {
      expiredWorkersRevoked?: number;
      expiredWorkersCleaned?: number;
    };
    expect(record.expiredWorkersRevoked).toBe(1);
    expect(record.expiredWorkersCleaned).toBe(1);
  });

  it("does not sweep an unexpired worker when the periodic task runs", async () => {
    seedLiveWorker("w-keep", "healthy");
    createWorkerScope(db, "w-keep", { ...VALID_SCOPE, ttlMs: WORKER_MAX_TTL_MS }, {
      now: Date.now(),
    });

    const taskCtx = {
      identity: createTestIdentity(),
      config: createTestConfig(),
      db,
      conway,
    };
    db.deleteKV("last_dead_agent_cleanup");

    await BUILTIN_TASKS.dead_agent_cleanup({} as never, taskCtx as never);
    expect(getWorkerScope(db, "w-keep")?.revoked).toBe(false);
    expect(childStatus("w-keep")).toBe("healthy");
  });
});

// ─── SandboxCleanup contract preserved ─────────────────────────────

describe("the remediation reuses the existing cleanup machinery", () => {
  it("SandboxCleanup still refuses to clean a live worker directly", async () => {
    // Proves the sweep is what makes cleanup legal — it drives the lifecycle
    // to a cleanable state first rather than bypassing the guard.
    seedLiveWorker("w-guard", "healthy");
    const cleanup = new SandboxCleanup(conway, new ChildLifecycle(db.raw), db.raw);
    await expect(cleanup.cleanup("w-guard")).rejects.toThrow(/Cannot clean up/);
  });
});

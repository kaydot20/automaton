/**
 * M1-B2 Minimum Reserve Enforcement — Regression Tests
 *
 * Covers the fail-closed minimum-reserve invariant:
 * - checkReserve boundary: exact reserve allowed, one cent below denied
 * - malformed reserve / amount / balance: denied, never coerced
 * - zero reserve and above-reserve behavior
 * - transfer_credits / fund_child tool paths (denial + no side effects)
 * - SimpleFundingProtocol.fundChild helper path (orchestrator bypass closed)
 *
 * x402 payment-path and auto-topup reconciliation tests live in
 * reserve-x402.test.ts (network-layer mocking).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import Database from "better-sqlite3";
import path from "path";
import os from "os";
import fs from "fs";
import { checkReserve, validateSpendCents } from "../conway/reserve.js";
import { createBuiltinTools, executeTool } from "../agent/tools.js";
import { SimpleFundingProtocol } from "../orchestration/simple-tracker.js";
import { DEFAULT_TREASURY_POLICY } from "../types.js";
import type {
  AutomatonTool,
  ToolContext,
  ToolCallResult,
} from "../types.js";

// ─── checkReserve core invariant ────────────────────────────────

describe("checkReserve core invariant", () => {
  it("allows spend when post-spend balance is above the reserve", () => {
    // 5000 - 1000 = 4000 >= 1000
    expect(checkReserve(1000, 5000, 1000)).toEqual({ allowed: true });
  });

  it("allows spend landing EXACTLY at the reserve (inclusive boundary)", () => {
    // 2000 - 1000 = 1000 == reserve → allowed
    expect(checkReserve(1000, 2000, 1000)).toEqual({ allowed: true });
  });

  it("denies spend one cent below the reserve", () => {
    // 2000 - 1001 = 999 < 1000 → denied
    const result = checkReserve(1001, 2000, 1000);
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reasonCode).toBe("MINIMUM_RESERVE");
    }
  });

  it("denies any spend when balance is already at the reserve", () => {
    const result = checkReserve(1, 1000, 1000);
    expect(result.allowed).toBe(false);
  });

  it("denies zero-reserve config only when the balance itself goes negative", () => {
    // reserve 0: spending the entire balance is allowed...
    expect(checkReserve(500, 500, 0)).toEqual({ allowed: true });
    // ...but overdrawing is not
    expect(checkReserve(501, 500, 0).allowed).toBe(false);
  });

  it("denies spending more than the balance even with a zero reserve", () => {
    expect(checkReserve(100, 50, 0).allowed).toBe(false);
  });

  describe("malformed amount: denied, never coerced", () => {
    const cases = [
      ["NaN", Number.NaN],
      ["+Infinity", Number.POSITIVE_INFINITY],
      ["-Infinity", Number.NEGATIVE_INFINITY],
      ["negative", -1],
      ["negative fraction", -0.5],
      ["string number", "100"],
      ["numeric string with spaces", " 100"],
      ["null", null],
      ["undefined", undefined],
      ["object", {}],
      ["array", [100]],
      ["boolean", true],
      ["bigint", 100n],
    ] as const;

    for (const [label, value] of cases) {
      it(`denies amount: ${label}`, () => {
        const result = checkReserve(value as never, 5000, 1000);
        expect(result.allowed).toBe(false);
        if (!result.allowed) {
          expect(result.reasonCode).toBe("RESERVE_INPUT_INVALID");
          expect(result.message).toContain("Malformed spend amount");
        }
      });
    }
  });

  describe("malformed balance: denied, never coerced", () => {
    it("denies NaN balance", () => {
      const result = checkReserve(100, Number.NaN, 1000);
      expect(result.allowed).toBe(false);
      if (!result.allowed) expect(result.reasonCode).toBe("RESERVE_INPUT_INVALID");
    });

    it("denies negative balance (fail-closed on unavailable-balance sentinels)", () => {
      // getFinancialState returns creditsCents === -1 when the balance API
      // is unreachable with no cache. That sentinel must DENY, not pass.
      const result = checkReserve(100, -1, 1000);
      expect(result.allowed).toBe(false);
      if (!result.allowed) expect(result.reasonCode).toBe("RESERVE_INPUT_INVALID");
    });

    it("denies string balance (type confusion)", () => {
      const result = checkReserve(100, "5000" as never, 1000);
      expect(result.allowed).toBe(false);
      if (!result.allowed) expect(result.reasonCode).toBe("RESERVE_INPUT_INVALID");
    });

    it("denies infinite balance", () => {
      expect(checkReserve(100, Number.POSITIVE_INFINITY, 1000).allowed).toBe(false);
    });
  });

  describe("malformed reserve config: denied, never coerced", () => {
    it("denies a string reserve", () => {
      const result = checkReserve(100, 5000, "1000" as never);
      expect(result.allowed).toBe(false);
      if (!result.allowed) expect(result.reasonCode).toBe("RESERVE_INPUT_INVALID");
    });

    it("denies an undefined reserve (missing policy)", () => {
      const result = checkReserve(100, 5000, undefined);
      expect(result.allowed).toBe(false);
      if (!result.allowed) expect(result.reasonCode).toBe("RESERVE_INPUT_INVALID");
    });

    it("denies a negative reserve", () => {
      expect(checkReserve(100, 5000, -5).allowed).toBe(false);
    });
  });

  describe("validateSpendCents", () => {
    it("accepts finite non-negative numbers including 0", () => {
      expect(validateSpendCents(0)).toBe(0);
      expect(validateSpendCents(1000)).toBe(1000);
      expect(validateSpendCents(0.5)).toBe(0.5);
    });

    it("returns null for malformed input", () => {
      expect(validateSpendCents("100")).toBeNull();
      expect(validateSpendCents(Number.NaN)).toBeNull();
      expect(validateSpendCents(-0.01)).toBeNull();
      expect(validateSpendCents(undefined)).toBeNull();
      expect(validateSpendCents(null)).toBeNull();
    });
  });
});

// ─── Tool-level paths: transfer_credits / fund_child ────────────

const TOOL_SANDBOX_ID = "test-sandbox";

function makeMockConway(creditsCents: number) {
  return {
    getCreditsBalance: vi.fn().mockResolvedValue(creditsCents),
    transferCredits: vi
      .fn()
      .mockResolvedValue({ status: "pending", toAddress: "0xchild", transferId: "t1" }),
    exec: vi.fn(),
    readFile: vi.fn(),
    writeFile: vi.fn(),
  };
}

function makeToolContext(
  conway: ReturnType<typeof makeMockConway>,
  overrides?: Partial<{ db: any }>,
): ToolContext {
  const store = new Map<string, string>();
  const db = {
    insertTransaction: vi.fn(),
    getKV: (key: string) => store.get(key),
    setKV: (key: string, value: string) => void store.set(key, value),
    raw: { prepare: vi.fn() },
    ...overrides?.db,
  };
  return {
    identity: {
      sandboxId: TOOL_SANDBOX_ID,
      address: "0xparent",
      chainType: "evm",
    },
    config: {
      name: "test",
      conwayApiUrl: "https://api.test",
      chainType: "evm",
      treasuryPolicy: { ...DEFAULT_TREASURY_POLICY },
    },
    db,
    conway,
  } as unknown as ToolContext;
}

function findTool(name: string): AutomatonTool {
  const tool = createBuiltinTools(TOOL_SANDBOX_ID).find((t) => t.name === name);
  if (!tool) throw new Error(`tool ${name} not found`);
  return tool;
}

async function runTool(
  name: string,
  args: Record<string, unknown>,
  ctx: ToolContext,
): Promise<ToolCallResult> {
  return executeTool(name, args, [findTool(name)], ctx, undefined, undefined);
}

describe("transfer_credits reserve gate", () => {
  let ctx: ToolContext;
  let conway: ReturnType<typeof makeMockConway>;

  beforeEach(() => {
    // 1500 balance, 1000 reserve: max spendable = 500
    conway = makeMockConway(1500);
    ctx = makeToolContext(conway);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("allows a transfer that keeps balance above the reserve", async () => {
    const result = await runTool(
      "transfer_credits",
      { to_address: "0xchild", amount_cents: 400 },
      ctx,
    );
    expect(result.error).toBeUndefined();
    expect(conway.transferCredits).toHaveBeenCalledWith(
      "0xchild",
      400,
      undefined,
    );
  });

  it("allows a transfer landing exactly at the reserve", async () => {
    // 1500 - 500 = 1000 == reserve → allowed
    const result = await runTool(
      "transfer_credits",
      { to_address: "0xchild", amount_cents: 500 },
      ctx,
    );
    expect(result.error).toBeUndefined();
    expect(conway.transferCredits).toHaveBeenCalled();
  });

  it("denies a transfer one cent below the reserve boundary", async () => {
    // 1500 - 501 = 999 < 1000 → denied
    const result = await runTool(
      "transfer_credits",
      { to_address: "0xchild", amount_cents: 501 },
      ctx,
    );
    expect(result.result).toContain("minimum reserve");
    // NO side effects: no transfer call, no transaction recorded
    expect(conway.transferCredits).not.toHaveBeenCalled();
    expect(ctx.db.insertTransaction).not.toHaveBeenCalled();
  });

  it("denies malformed amounts without contacting the balance API", async () => {
    for (const amount of ["500", Number.NaN, -100, null, undefined]) {
      const result = await runTool(
        "transfer_credits",
        { to_address: "0xchild", amount_cents: amount as never },
        ctx,
      );
      expect(result.result).toContain("positive number");
    }
    expect(conway.getCreditsBalance).not.toHaveBeenCalled();
    expect(conway.transferCredits).not.toHaveBeenCalled();
    expect(ctx.db.insertTransaction).not.toHaveBeenCalled();
  });

  it("proves no side effects after a reserve denial (state unchanged)", async () => {
    const txCallsBefore = (ctx.db.insertTransaction as ReturnType<typeof vi.fn>).mock.calls.length;
    // 501 is under the half-balance guard (750) but breaches the reserve:
    // 1500 - 501 = 999 < 1000 → denied by the reserve gate specifically.
    await runTool(
      "transfer_credits",
      { to_address: "0xchild", amount_cents: 501 },
      ctx,
    );
    expect(conway.transferCredits).not.toHaveBeenCalled();
    expect(
      (ctx.db.insertTransaction as ReturnType<typeof vi.fn>).mock.calls.length,
    ).toBe(txCallsBefore);
  });
});

const CHILD_ADDRESS = "0x" + "1".repeat(40); // valid non-zero EVM address

describe("fund_child reserve gate", () => {
  let rawDb: Database.Database;
  let ctx: ToolContext;
  let conway: ReturnType<typeof makeMockConway>;
  let closeDb: () => void;

  beforeEach(() => {
    rawDb = new Database(":memory:");
    rawDb.exec(`
      CREATE TABLE children (
        id TEXT PRIMARY KEY,
        name TEXT,
        address TEXT,
        sandbox_id TEXT,
        genesis_prompt TEXT,
        creator_message TEXT,
        funded_amount_cents INTEGER DEFAULT 0,
        status TEXT,
        created_at TEXT,
        last_checked TEXT,
        role TEXT
      );
    `);
    rawDb
      .prepare(
        "INSERT INTO children (id, name, address, sandbox_id, genesis_prompt, funded_amount_cents, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run("c1", "child-1", CHILD_ADDRESS, "sb-1", "p", 0, "wallet_verified", new Date().toISOString());

    const childRow = rawDb
      .prepare("SELECT * FROM children WHERE id = ?")
      .get("c1") as Record<string, unknown>;

    // 1500 balance, 1000 reserve: max fundable = 500
    conway = makeMockConway(1500);
    ctx = makeToolContext(conway);
    (ctx as any).db.getChildById = vi.fn().mockReturnValue(childRow);
    (ctx as any).db.raw = rawDb;
    closeDb = () => rawDb.close();
  });

  afterEach(() => {
    closeDb();
    vi.restoreAllMocks();
  });

  it("allows funding that keeps balance above the reserve", async () => {
    const result = await runTool("fund_child", { child_id: "c1", amount_cents: 300 }, ctx);
    expect(result.error).toBeUndefined();
    expect(conway.transferCredits).toHaveBeenCalledWith(
      CHILD_ADDRESS,
      300,
      "fund child c1",
    );
  });

  it("allows funding landing exactly at the reserve", async () => {
    const result = await runTool("fund_child", { child_id: "c1", amount_cents: 500 }, ctx);
    expect(result.error).toBeUndefined();
    expect(conway.transferCredits).toHaveBeenCalled();
  });

  it("denies funding one cent below the reserve boundary with no side effects", async () => {
    // 1500 - 501 = 999 < 1000 → denied
    const result = await runTool("fund_child", { child_id: "c1", amount_cents: 501 }, ctx);
    expect(result.result).toContain("minimum reserve");
    expect(conway.transferCredits).not.toHaveBeenCalled();
    expect(ctx.db.insertTransaction).not.toHaveBeenCalled();
    // funded_amount_cents unchanged
    const row = rawDb.prepare("SELECT funded_amount_cents FROM children WHERE id = ?").get("c1") as any;
    expect(row.funded_amount_cents).toBe(0);
    // lifecycle NOT transitioned to funded (status unchanged)
    const statusRow = rawDb.prepare("SELECT status FROM children WHERE id = ?").get("c1") as any;
    expect(statusRow.status).toBe("wallet_verified");
  });

  it("proves zero side effects after denial (transaction, funding, lifecycle)", async () => {
    const txBefore = (ctx.db.insertTransaction as ReturnType<typeof vi.fn>).mock.calls.length;
    // 501 is under the half-balance guard (750) but breaches the reserve.
    await runTool("fund_child", { child_id: "c1", amount_cents: 501 }, ctx);
    expect(conway.transferCredits).not.toHaveBeenCalled();
    expect(
      (ctx.db.insertTransaction as ReturnType<typeof vi.fn>).mock.calls.length,
    ).toBe(txBefore);
    const row = rawDb.prepare("SELECT funded_amount_cents, status FROM children WHERE id = ?").get("c1") as any;
    expect(row.funded_amount_cents).toBe(0);
    expect(row.status).toBe("wallet_verified");
  });
});

// ─── Helper-level path: SimpleFundingProtocol (orchestrator) ────

describe("SimpleFundingProtocol reserve gate (helper-level bypass closed)", () => {
  let rawDb: Database.Database;

  beforeEach(() => {
    rawDb = new Database(":memory:");
    rawDb.exec(`
      CREATE TABLE children (
        id TEXT PRIMARY KEY,
        name TEXT,
        address TEXT,
        sandbox_id TEXT,
        genesis_prompt TEXT,
        funded_amount_cents INTEGER DEFAULT 0,
        status TEXT,
        created_at TEXT
      );
    `);
    rawDb
      .prepare(
        "INSERT INTO children (id, name, address, sandbox_id, genesis_prompt, funded_amount_cents, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run("c1", "child-1", "0xchild", "sb-1", "p", 0, "running", new Date().toISOString());
  });

  afterEach(() => {
    rawDb.close();
  });

  function makeFunding(conway: any) {
    return new SimpleFundingProtocol(conway, { address: "0xparent" } as any, {
      raw: rawDb,
    } as any);
  }

  it("denies funding that would breach the reserve (previously unchecked)", async () => {
    // Balance 1500, reserve 1000: 600 would leave 900 → denied.
    const conway = {
      transferCredits: vi.fn(),
      getCreditsBalance: vi.fn().mockResolvedValue(1500),
    };
    const funding = makeFunding(conway);

    const result = await funding.fundChild("0xchild", 600);

    expect(result.success).toBe(false);
    expect(conway.transferCredits).not.toHaveBeenCalled();
  });

  it("allows funding landing exactly at the reserve (boundary)", async () => {
    const conway = {
      transferCredits: vi.fn().mockResolvedValue({ status: "ok" }),
      getCreditsBalance: vi.fn().mockResolvedValue(1100),
    };
    const funding = makeFunding(conway);

    const result = await funding.fundChild("0xchild", 100);

    expect(result.success).toBe(true);
    expect(conway.transferCredits).toHaveBeenCalledWith(
      "0xchild",
      100,
      "Task funding from orchestrator",
    );
  });

  it("denies when balance fetch throws (fail-closed)", async () => {
    const conway = {
      transferCredits: vi.fn(),
      getCreditsBalance: vi.fn().mockRejectedValue(new Error("api down")),
    };
    const funding = makeFunding(conway);

    const result = await funding.fundChild("0xchild", 100);

    expect(result.success).toBe(false);
    expect(conway.transferCredits).not.toHaveBeenCalled();
  });

  it("denies when balance is the unavailable sentinel (-1)", async () => {
    const conway = {
      transferCredits: vi.fn(),
      getCreditsBalance: vi.fn().mockResolvedValue(-1),
    };
    const funding = makeFunding(conway);

    const result = await funding.fundChild("0xchild", 100);

    expect(result.success).toBe(false);
    expect(conway.transferCredits).not.toHaveBeenCalled();
  });
});

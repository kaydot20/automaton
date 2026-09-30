/**
 * M1-B2 Minimum Reserve Enforcement — x402 Payment Path + Auto-Topup
 * Reconciliation Tests
 *
 * Network layer is stubbed at globalThis.fetch:
 * - Requests to the fake merchant/API URL exercise the 402 → reserve gate →
 *   sign → paid-retry flow in x402Fetch.
 * - All other requests are treated as JSON-RPC (viem balance reads) and
 *   return a canned eth_call result for the wallet's USDC balance.
 *
 * Covered:
 * - x402 reserve boundary (exact reserve allowed, one cent below denied)
 * - denial before signing: no X-Payment ever leaves the process
 * - per-payment cap precedence + conservative default when cap is
 *   missing/malformed (previously the helper path was entirely unchecked)
 * - sub-cent payment rounding against the spender
 * - auto-topup reconciliation: self-topup is the USDC→credits income path
 *   (reserve exempt, solvency enforced); cross-recipient topup enforces the
 *   full reserve invariant; malformed tier or unavailable balance → deny
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { x402Fetch } from "../conway/x402.js";
import { topupCredits, bootstrapTopup, TOPUP_TIERS } from "../conway/topup.js";
import { executeTool, createBuiltinTools } from "../agent/tools.js";
import { DEFAULT_TREASURY_POLICY } from "../types.js";
import type { ToolContext } from "../types.js";

const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const MERCHANT_URL = "https://pay.conway.test/api";
const ACCOUNT = privateKeyToAccount(`0x${"11".repeat(32)}`);
const OTHER_ADDRESS = `0x${"9".repeat(40)}`;

/** Build a 402 payment-required response (x402 v1, decimal-dollar amounts). */
function paymentRequired(maxAmountRequired: string, x402Version = 1): Response {
  const body = {
    x402Version,
    accepts: [
      {
        scheme: "exact",
        network: "eip155:8453",
        maxAmountRequired,
        payToAddress: OTHER_ADDRESS,
        requiredDeadlineSeconds: 60,
        usdcAddress: USDC_BASE,
      },
    ],
  };
  return new Response(JSON.stringify(body), {
    status: 402,
    headers: {
      "content-type": "application/json",
      "X-Payment-Required": JSON.stringify(body),
    },
  });
}

/**
 * Install a fetch stub. balanceAtomic is the wallet's USDC balance in atomic
 * units (6 decimals); pass null to simulate a failing RPC (unavailable
 * balance source).
 */
function stubFetch(options: {
  balanceAtomic: bigint | null;
  merchantResponse?: (paid: boolean, headers: Record<string, unknown>) => Response;
}) {
  const requests: { url: string; paid: boolean; headers: Record<string, unknown> }[] = [];

  const impl = async (input: any, init?: any): Promise<Response> => {
    const url = typeof input === "string" ? input : input?.url ?? String(input);
    if (url.includes("/pay/") || url.includes("pay.conway.test")) {
      const headers = (init?.headers ?? {}) as Record<string, unknown>;
      const paid = "X-Payment" in headers;
      requests.push({ url, paid, headers });
      if (!paid) {
        return options.merchantResponse?.(false, headers) ?? paymentRequired("0.10");
      }
      return (
        options.merchantResponse?.(true, headers) ??
        new Response(JSON.stringify({ ok: true }), { status: 200 })
      );
    }

    // JSON-RPC (viem balance read)
    let rpcBody: any = {};
    try {
      rpcBody = JSON.parse(typeof init?.body === "string" ? init.body : "{}");
    } catch {
      rpcBody = {};
    }
    if (options.balanceAtomic === null && rpcBody.method === "eth_call") {
      throw new Error("rpc unavailable");
    }
    const result = rpcBody.method === "eth_call"
      ? `0x${(options.balanceAtomic ?? 0n).toString(16).padStart(64, "0")}`
      : "0x2105";
    return new Response(
      JSON.stringify({ jsonrpc: "2.0", id: rpcBody.id ?? 1, result }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };

  const spy = vi.fn(impl);
  const original = globalThis.fetch;
  globalThis.fetch = spy as unknown as typeof fetch;
  return {
    requests,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

/** Convert whole cents to USDC atomic units (6 decimals). */
function centsToAtomic(cents: number): bigint {
  return BigInt(cents) * 10_000n;
}

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("x402Fetch reserve gate (payment path)", () => {
  it("denies payment when wallet USDC would drop below the reserve — no signature leaves", async () => {
    // Balance $10.05 (1005¢); payment 10¢ → post-spend 995 < 1000 reserve.
    const stub = stubFetch({ balanceAtomic: centsToAtomic(1005) });

    const result = await x402Fetch(MERCHANT_URL, ACCOUNT, "GET", undefined, undefined, 100);

    stub.restore();
    expect(result.success).toBe(false);
    expect(result.error).toContain("minimum reserve");
    expect(stub.requests).toHaveLength(1);
    expect(stub.requests[0].paid).toBe(false);
  });

  it("allows payment landing EXACTLY at the reserve (inclusive boundary)", async () => {
    // Balance $10.10 (1010¢); payment 10¢ → post-spend exactly 1000 == reserve.
    const stub = stubFetch({ balanceAtomic: centsToAtomic(1010) });

    const result = await x402Fetch(MERCHANT_URL, ACCOUNT, "GET", undefined, undefined, 100);

    stub.restore();
    expect(result.success).toBe(true);
    expect(stub.requests).toHaveLength(2);
    expect(stub.requests[1].paid).toBe(true);
    expect(stub.requests[1].headers["X-Payment"]).toBeTruthy();
  });

  it("denies payment one cent below the reserve boundary", async () => {
    // Balance $10.09 (1009¢); payment 10¢ → post-spend 999 < 1000.
    const stub = stubFetch({ balanceAtomic: centsToAtomic(1009) });

    const result = await x402Fetch(MERCHANT_URL, ACCOUNT, "GET", undefined, undefined, 100);

    stub.restore();
    expect(result.success).toBe(false);
    expect(result.error).toContain("minimum reserve");
    expect(stub.requests).toHaveLength(1);
    expect(stub.requests[0].paid).toBe(false);
  });

  it("enforces the per-payment cap before the reserve (cap precedence)", async () => {
    // Huge balance; payment $5 (500¢) exceeds the 100¢ cap → denied by cap.
    const stub = stubFetch({
      balanceAtomic: centsToAtomic(1_000_000),
      merchantResponse: () => paymentRequired("5.00"),
    });

    const result = await x402Fetch(MERCHANT_URL, ACCOUNT, "GET", undefined, undefined, 100);

    stub.restore();
    expect(result.success).toBe(false);
    expect(result.error).toContain("exceeds max allowed 100");
  });

  it("applies the conservative default cap when maxPaymentCents is undefined (helper path no longer unchecked)", async () => {
    // topup.ts previously called x402Fetch with no cap: any payment amount
    // was signed. Now undefined falls back to maxX402PaymentCents (100¢).
    const stub = stubFetch({
      balanceAtomic: centsToAtomic(1_000_000),
      merchantResponse: () => paymentRequired("5.00"),
    });

    const result = await x402Fetch(MERCHANT_URL, ACCOUNT, "GET", undefined, undefined, undefined);

    stub.restore();
    expect(result.success).toBe(false);
    expect(result.error).toContain("exceeds max allowed 100");
  });

  it("falls back to the conservative default when maxPaymentCents is malformed (NaN)", async () => {
    const stub = stubFetch({
      balanceAtomic: centsToAtomic(1_000_000),
      merchantResponse: () => paymentRequired("5.00"),
    });

    const result = await x402Fetch(MERCHANT_URL, ACCOUNT, "GET", undefined, undefined, Number.NaN);

    stub.restore();
    expect(result.success).toBe(false);
    expect(result.error).toContain("exceeds max allowed 100");
  });

  it("rounds sub-cent payments UP against the spender at the boundary", async () => {
    // Balance exactly $10 (1000¢ = reserve); payment 0.4¢. True post-spend
    // = 999.6¢ < reserve → must deny. Without ceiling the payment would
    // floor to 0¢ and the payment would slip through.
    const body = {
      x402Version: 2,
      accepts: [
        {
          scheme: "exact",
          network: "eip155:8453",
          maxAmountRequired: "4000", // 4000 atomic = 0.4 cents (v2 = raw atomic)
          payToAddress: OTHER_ADDRESS,
          requiredDeadlineSeconds: 60,
          usdcAddress: USDC_BASE,
        },
      ],
    };
    const stub = stubFetch({
      balanceAtomic: centsToAtomic(1000),
      merchantResponse: () =>
        new Response(JSON.stringify(body), {
          status: 402,
          headers: {
            "content-type": "application/json",
            "X-Payment-Required": JSON.stringify(body),
          },
        }),
    });

    const result = await x402Fetch(MERCHANT_URL, ACCOUNT, "GET", undefined, undefined, 100);

    stub.restore();
    expect(result.success).toBe(false);
    expect(result.error).toContain("minimum reserve");
  });

  it("skips the reserve only when the balance source is unavailable — amount cap still applies", async () => {
    // RPC fails (balance unavailable): reserve is skipped (documented
    // fail-open window for transient infrastructure failure), the payment
    // cap still holds, and the paid retry proceeds.
    const stub = stubFetch({ balanceAtomic: null });

    const result = await x402Fetch(MERCHANT_URL, ACCOUNT, "GET", undefined, undefined, 100);

    stub.restore();
    expect(result.success).toBe(true);
    expect(stub.requests.filter((r) => r.paid)).toHaveLength(1);
  });
});

describe("x402_fetch tool path (same invariant through executeTool)", () => {
  function makeCtx(): ToolContext {
    const store = new Map<string, string>();
    return {
      identity: {
        sandboxId: "sb-test",
        address: ACCOUNT.address,
        account: ACCOUNT,
        chainType: "evm",
      },
      config: {
        name: "test",
        conwayApiUrl: "https://api.conway.test",
        chainType: "evm",
        treasuryPolicy: { ...DEFAULT_TREASURY_POLICY },
      },
      db: {
        insertTransaction: vi.fn(),
        getKV: (k: string) => store.get(k),
        setKV: (k: string, v: string) => void store.set(k, v),
      },
    } as unknown as ToolContext;
  }

  it("surfaces the reserve denial through the tool result without paying", async () => {
    const stub = stubFetch({ balanceAtomic: centsToAtomic(1005) });
    const tool = createBuiltinTools("sb-test").find((t) => t.name === "x402_fetch");
    if (!tool) throw new Error("x402_fetch tool not found");
    const ctx = makeCtx();

    const result = await executeTool(
      "x402_fetch",
      { url: MERCHANT_URL },
      [tool],
      ctx,
      undefined,
      undefined,
    );

    stub.restore();
    expect(result.result).toContain("x402 fetch failed");
    expect(result.result).toContain("minimum reserve");
    expect(stub.requests.filter((r) => r.paid)).toHaveLength(0);
  });

  it("pays successfully when the balance is above the reserve", async () => {
    const stub = stubFetch({ balanceAtomic: centsToAtomic(5000) });
    const tool = createBuiltinTools("sb-test").find((t) => t.name === "x402_fetch");
    if (!tool) throw new Error("x402_fetch tool not found");
    const ctx = makeCtx();

    const result = await executeTool(
      "x402_fetch",
      { url: MERCHANT_URL },
      [tool],
      ctx,
      undefined,
      undefined,
    );

    stub.restore();
    expect(result.result).toContain("x402 fetch succeeded");
    expect(stub.requests.filter((r) => r.paid)).toHaveLength(1);
  });
});

describe("auto-topup reconciliation (topup.ts)", () => {
  it("self-topup remains possible below the naive USDC reserve (income path)", async () => {
    // Balance $8; $5 tier self-topup. A naive reserve charge ($10) would
    // block this — the starvation lock. Self-topup converts USDC into the
    // agent's own credits, so it must proceed (solvency holds: 8 >= 5).
    const stub = stubFetch({ balanceAtomic: centsToAtomic(800) });

    const result = await topupCredits("https://api.conway.test", ACCOUNT, 5);

    stub.restore();
    expect(result.success).toBe(true);
    expect(result.amountUsd).toBe(5);
    expect(stub.requests.filter((r) => r.paid)).toHaveLength(1);
  });

  it("self-topup is blocked when the wallet cannot cover the payment (solvency, fail-closed)", async () => {
    // Balance $3 < $5 tier: not enough USDC to pay — blocked before signing.
    const stub = stubFetch({ balanceAtomic: centsToAtomic(300) });

    const result = await topupCredits("https://api.conway.test", ACCOUNT, 5);

    stub.restore();
    expect(result.success).toBe(false);
    expect(stub.requests.filter((r) => r.paid)).toHaveLength(0);
  });

  it("topup is blocked on a malformed tier amount (fail-closed, no network)", async () => {
    const stub = stubFetch({ balanceAtomic: centsToAtomic(1_000_000) });

    for (const bad of [7, Number.NaN, "5", -5, Number.POSITIVE_INFINITY] as const) {
      const result = await topupCredits(
        "https://api.conway.test",
        ACCOUNT,
        bad as never,
      );
      expect(result.success).toBe(false);
      expect(result.error).toContain("Invalid topup amount");
    }
    stub.restore();
    // No payment requests were made for malformed amounts.
    expect(stub.requests.filter((r) => r.paid)).toHaveLength(0);
  });

  it("topup is blocked when the USDC balance source fails (fail-closed)", async () => {
    const stub = stubFetch({ balanceAtomic: null });

    const result = await topupCredits("https://api.conway.test", ACCOUNT, 5);

    stub.restore();
    expect(result.success).toBe(false);
    expect(stub.requests.filter((r) => r.paid)).toHaveLength(0);
  });

  it("cross-recipient topup enforces the full reserve invariant", async () => {
    // Balance $30; $25 tier to ANOTHER address leaves $5 < $10 reserve → deny.
    const stub = stubFetch({ balanceAtomic: centsToAtomic(3000) });

    const result = await topupCredits(
      "https://api.conway.test",
      ACCOUNT,
      25,
      OTHER_ADDRESS,
    );

    stub.restore();
    expect(result.success).toBe(false);
    expect(stub.requests.filter((r) => r.paid)).toHaveLength(0);
  });

  it("cross-recipient topup above the reserve is allowed", async () => {
    // Balance $40; $25 to another address leaves $15 >= $10 → allowed.
    const stub = stubFetch({
      balanceAtomic: centsToAtomic(4000),
      merchantResponse: (paid) =>
        paid
          ? new Response(JSON.stringify({ credits_cents: 2500 }), { status: 200 })
          : paymentRequired("25.00"),
    });

    const result = await topupCredits(
      "https://api.conway.test",
      ACCOUNT,
      25,
      OTHER_ADDRESS,
    );

    stub.restore();
    expect(result.success).toBe(true);
    expect(stub.requests.filter((r) => r.paid)).toHaveLength(1);
  });

  it("bootstrapTopup (heartbeat/loop inline auto-topup) still rescues a critical agent", async () => {
    // Credits 100¢ (< 500 threshold), USDC $8 → buys the $5 tier for SELF.
    // The full 402 → pay flow must complete for the rescue to count.
    const stub = stubFetch({
      balanceAtomic: centsToAtomic(800),
      merchantResponse: (paid) =>
        paid
          ? new Response(JSON.stringify({ credits_cents: 500 }), { status: 200 })
          : paymentRequired("5.00"),
    });

    const result = await bootstrapTopup({
      apiUrl: "https://api.conway.test",
      account: ACCOUNT,
      creditsCents: 100,
      chainType: "evm",
    });

    stub.restore();
    expect(result?.success).toBe(true);
    expect(result?.amountUsd).toBe(TOPUP_TIERS[0]);
    expect(result?.creditsCentsAdded).toBe(500);
    expect(stub.requests.filter((r) => r.paid)).toHaveLength(1);
  });

  it("bootstrapTopup treats a malformed server-reported credit amount as zero, not coerced", async () => {
    const stub = stubFetch({
      balanceAtomic: centsToAtomic(800),
      merchantResponse: (paid) =>
        paid
          ? new Response(JSON.stringify({ credits_cents: "lots" }), { status: 200 })
          : paymentRequired("5.00"),
    });

    const result = await bootstrapTopup({
      apiUrl: "https://api.conway.test",
      account: ACCOUNT,
      creditsCents: 100,
      chainType: "evm",
    });

    stub.restore();
    expect(result?.success).toBe(true);
    expect(result?.creditsCentsAdded).toBe(0);
    expect(stub.requests.filter((r) => r.paid)).toHaveLength(1);
  });
});

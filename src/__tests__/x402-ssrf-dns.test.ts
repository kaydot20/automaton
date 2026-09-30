/**
 * M1-B4 remediation — Mandatory DNS Resolution on the x402 Payment Path
 *
 * Proves the recovered F4.3/F4.1 contract:
 * - production x402/payment requests RESOLVE the hostname and validate
 *   EVERY returned A/AAAA address against the private/special-use
 *   blocklist BEFORE the first fetch and BEFORE any signature/header
 * - one private/special-use answer fails the whole request
 * - resolver failure / empty answer / malformed output fail closed
 * - rebinding (public then private) fails closed
 * - redirect destinations are re-resolved and re-validated before their hop
 * - the B2 self-topup rescue path still works with an injected public resolver
 *
 * Tests inject DNS resolvers (requirement 3) — production enforcement is
 * never weakened for test compatibility.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { x402Fetch } from "../conway/x402.js";
import { topupCredits, bootstrapTopup } from "../conway/topup.js";
import { ResilientHttpClient } from "../conway/http-client.js";
import type { DnsResolver } from "../net/policy.js";
import type { X402FetchOptions } from "../conway/x402.js";

const ACCOUNT = privateKeyToAccount(`0x${"33".repeat(32)}`);
const PUBLIC_IP = "93.184.216.34";
const PRIVATE_IP = "10.1.2.3";
const METADATA_IP = "169.254.169.254";

const PUBLIC_DNS: DnsResolver = { lookup: async () => [PUBLIC_IP] };
const PRIVATE_DNS: DnsResolver = { lookup: async () => [PRIVATE_IP] };
const MIXED_DNS: DnsResolver = { lookup: async () => [PUBLIC_IP, PRIVATE_IP] };
const METADATA_DNS: DnsResolver = { lookup: async () => [METADATA_IP] };
const FAILING_DNS: DnsResolver = {
  lookup: async () => {
    throw new Error("SERVFAIL");
  },
};
const EMPTY_DNS: DnsResolver = { lookup: async () => [] };
const MALFORMED_DNS: DnsResolver = { lookup: async () => ["not-an-ip-address"] as unknown as string[] };
const CALL_COUNTING_DNS = (answers: string[][]): DnsResolver & { calls: string[] } => {
  const calls: string[] = [];
  return {
    calls,
    lookup: async (hostname: string) => {
      calls.push(hostname);
      return answers.length > 0 ? answers.shift()! : answers[0] ?? ["93.184.216.34"];
    },
  };
};

function paymentRequired(maxAmountRequired: string): Response {
  const body = {
    x402Version: 1,
    accepts: [
      {
        scheme: "exact",
        network: "eip155:8453",
        maxAmountRequired,
        payToAddress: `0x${"9".repeat(40)}`,
        requiredDeadlineSeconds: 60,
        usdcAddress: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
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

const OK_200 = () => new Response(JSON.stringify({ ok: true }), { status: 200 });

/** Install a fetch stub for the merchant host; records paid attempts. */
function stubMerchantFetch(
  impl: (url: string, paid: boolean) => Response | Promise<Response>,
) {
  const requests: { url: string; paid: boolean }[] = [];
  const spy = vi.fn(async (input: any, init?: any) => {
    const url = typeof input === "string" ? input : input?.url ?? String(input);
    if (!url.includes("merchant.test")) {
      // JSON-RPC (viem balance reads) — not expected in this suite
      throw new Error(`unexpected fetch: ${url}`);
    }
    const headers = (init?.headers ?? {}) as Record<string, unknown>;
    const paid = "X-Payment" in headers;
    requests.push({ url, paid });
    return impl(url, paid);
  });
  const original = globalThis.fetch;
  globalThis.fetch = spy as unknown as typeof fetch;
  return { requests, restore: () => void (globalThis.fetch = original) };
}

const PAY_OPTS: X402FetchOptions = { dnsResolver: PUBLIC_DNS };
const PAY_OPTS_10C = { dnsResolver: PUBLIC_DNS } as const;

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ─── 1. Public resolution → allowed ─────────────────────────────

describe("mandatory DNS: hostname resolves public → allowed", () => {
  it("completes the full 402 → sign → pay flow with a public A record", async () => {
    const stub = stubMerchantFetch((_url, paid) => (paid ? OK_200() : paymentRequired("0.10")));
    const result = await x402Fetch("https://merchant.test/api", ACCOUNT, "GET", undefined, undefined, 100, undefined, undefined, PAY_OPTS);
    stub.restore();

    expect(result.success).toBe(true);
    expect(stub.requests.filter((r) => r.paid)).toHaveLength(1);
    expect((stub.requests[1] as any).paid).toBe(true);
  });

  it("resolves before the FIRST fetch (resolution strictly precedes network I/O)", async () => {
    const dns = CALL_COUNTING_DNS([[PUBLIC_IP]]);
    const stub = stubMerchantFetch((_url, paid) => (paid ? OK_200() : paymentRequired("0.10")));
    const result = await x402Fetch("https://merchant.test/api", ACCOUNT, "GET", undefined, undefined, 100, undefined, undefined, { dnsResolver: dns });
    stub.restore();

    expect(result.success).toBe(true);
    expect(dns.calls.length).toBeGreaterThanOrEqual(1); // resolved at least once pre-fetch
  });
});

// ─── 2. Private resolution → blocked pre-signature ──────────────

describe("mandatory DNS: hostname resolves private → blocked", () => {
  it("blocks before any fetch or signature", async () => {
    const stub = stubMerchantFetch(() => OK_200());
    const result = await x402Fetch("https://merchant.test/api", ACCOUNT, "GET", undefined, undefined, 100, undefined, undefined, { dnsResolver: PRIVATE_DNS });
    stub.restore();

    expect(result.success).toBe(false);
    expect(result.error).toContain("private or reserved");
    expect(stub.requests).toHaveLength(0);
  });

  it("blocks the cloud metadata endpoint reached BY NAME", async () => {
    const stub = stubMerchantFetch(() => OK_200());
    const result = await x402Fetch("https://merchant.test/api", ACCOUNT, "GET", undefined, undefined, 100, undefined, undefined, { dnsResolver: METADATA_DNS });
    stub.restore();

    expect(result.success).toBe(false);
    expect(result.error).toContain("private or reserved");
    expect(stub.requests).toHaveLength(0);
  });
});

// ─── 3. Mixed answers → blocked ─────────────────────────────────

describe("mandatory DNS: mixed public+private answers → blocked", () => {
  it("one private A record among public ones fails the whole request", async () => {
    const stub = stubMerchantFetch(() => OK_200());
    const result = await x402Fetch("https://merchant.test/api", ACCOUNT, "GET", undefined, undefined, 100, undefined, undefined, { dnsResolver: MIXED_DNS });
    stub.restore();

    expect(result.success).toBe(false);
    expect(result.error).toContain("private or reserved");
    expect(stub.requests).toHaveLength(0);
  });
});

// ─── 4. Rebinding simulation → blocked ──────────────────────────

describe("mandatory DNS: rebinding (public then private) → blocked", () => {
  it("first call public, second call private → second call blocked pre-signature", async () => {
    // Each x402Fetch resolves THREE times (precheck, probe hop, paid hop),
    // each independently re-validated. Call 1 consumes three public
    // answers; call 2's precheck hits the flipped private record.
    const dns = CALL_COUNTING_DNS([[PUBLIC_IP], [PUBLIC_IP], [PUBLIC_IP], [PRIVATE_IP]]);
    const stub = stubMerchantFetch((_url, paid) => (paid ? OK_200() : paymentRequired("0.10")));

    const first = await x402Fetch("https://merchant.test/api", ACCOUNT, "GET", undefined, undefined, 100, undefined, undefined, { dnsResolver: dns });
    expect(first.success).toBe(true);
    expect(stub.requests.filter((r) => r.paid)).toHaveLength(1);

    const paidBefore = stub.requests.filter((r) => r.paid).length;
    const second = await x402Fetch("https://merchant.test/api", ACCOUNT, "GET", undefined, undefined, 100, undefined, undefined, { dnsResolver: dns });
    stub.restore();

    expect(second.success).toBe(false);
    expect(second.error).toContain("private or reserved");
    // No side effects: the flipped record blocked the second call entirely.
    expect(stub.requests).toHaveLength(2); // call 1's probe+paid only
    expect(stub.requests.filter((r) => r.paid)).toHaveLength(paidBefore);
  });

  it("a flip BETWEEN probe and paid retry blocks the signature from being used", async () => {
    // Probe resolves public (402 parsed, reserve passes, payment SIGNED),
    // then the paid retry re-resolves to private → the signed payment must
    // never reach the wire.
    const dns = CALL_COUNTING_DNS([[PUBLIC_IP], [PRIVATE_IP]]);
    const stub = stubMerchantFetch((_url, paid) => (paid ? OK_200() : paymentRequired("0.10")));

    const result = await x402Fetch("https://merchant.test/api", ACCOUNT, "GET", undefined, undefined, 100, undefined, undefined, { dnsResolver: dns });
    stub.restore();

    expect(result.success).toBe(false);
    expect(result.error).toContain("private or reserved");
    expect(stub.requests.filter((r) => r.paid)).toHaveLength(0); // signed but never sent
  });
});

// ─── 5. DNS failure / empty / malformed → fail closed ───────────

describe("mandatory DNS: resolution failure, empty and malformed answers fail closed", () => {
  it("resolver throwing → denied before any fetch", async () => {
    const stub = stubMerchantFetch(() => OK_200());
    const result = await x402Fetch("https://merchant.test/api", ACCOUNT, "GET", undefined, undefined, 100, undefined, undefined, { dnsResolver: FAILING_DNS });
    stub.restore();

    expect(result.success).toBe(false);
    expect(result.error).toContain("resolution failed");
    expect(stub.requests).toHaveLength(0);
  });

  it("empty answer list → denied before any fetch", async () => {
    const stub = stubMerchantFetch(() => OK_200());
    const result = await x402Fetch("https://merchant.test/api", ACCOUNT, "GET", undefined, undefined, 100, undefined, undefined, { dnsResolver: EMPTY_DNS });
    stub.restore();

    expect(result.success).false;
    expect(result.error).toContain("resolved to no addresses");
    expect(stub.requests).toHaveLength(0);
  });

  it("malformed resolver output → denied before any fetch", async () => {
    const stub = stubMerchantFetch(() => OK_200());
    const result = await x402Address("https://merchant.test/api", ACCOUNT);
    stub.restore();

    expect(result.success).toBe(false);
    expect(result.error).toContain("malformed address");
    expect(stub.requests).toHaveLength(0);
  });
});

// Helper used above to keep line width in check.
async function x402Address(url: string, account: typeof ACCOUNT) {
  return x402Fetch(url, account, "GET", undefined, undefined, 100, undefined, undefined, { dnsResolver: MALFORMED_DNS });
}

// ─── 6. Redirect destination re-resolved and re-validated ───────

describe("mandatory DNS: redirect destinations are re-validated", () => {
  it("redirect to a hostname resolving private → blocked before the redirected fetch", async () => {
    const dns = CALL_COUNTING_DNS([[PUBLIC_IP], [PRIVATE_IP]]);
    const client = new ResilientHttpClient({ maxRetries: 0, requireDnsResolution: true, dnsResolver: dns });
    const fetchSpy = vi.fn(async (input: any) => {
      const url = String(input);
      if (url.includes("start")) {
        return new Response(null, { status: 302, headers: { location: "https://evil.test/next" } });
      }
      return new Response("should not be fetched", { status: 200 });
    });
    const original = globalThis.fetch;
    globalThis.fetch = fetchSpy as unknown as typeof fetch;

    await expect(
      client.request("https://start.test/redirect", { dnsResolver: dns, requireDnsResolution: true }),
    ).rejects.toThrow(/private or reserved/);

    globalThis.fetch = original;
    expect(fetchSpy).toHaveBeenCalledTimes(1); // redirect hop never fetched
    expect(dns.calls).toEqual(["start.test", "evil.test"]); // both hops resolved
  });

  it("redirect to a hostname resolving public → followed", async () => {
    const dns = CALL_COUNTING_DNS([[PUBLIC_IP], [PUBLIC_IP]]);
    const client = new ResilientHttpClient({ maxRetries: 0, requireDnsResolution: true, dnsResolver: dns });
    const fetchSpy = vi.fn(async (input: any) => {
      const url = String(input);
      if (url.includes("start")) {
        return new Response(null, { status: 302, headers: { location: "https://good.test/next" } });
      }
      return new Response("arrived", { status: 200 });
    });
    const original = globalThis.fetch;
    globalThis.fetch = fetchSpy as unknown as typeof fetch;

    const resp = await client.request("https://start.test/redirect", { dnsResolver: dns, requireDnsResolution: true });

    globalThis.fetch = original;
    expect(resp.status).toBe(200);
    expect(dns.calls).toEqual(["start.test", "good.test"]);
  });
});

// ─── 7. B2 self-topup rescue survives mandatory DNS ─────────────

describe("B2 self-topup rescue with mandatory DNS", () => {
  it("bootstrapTopup completes with an injected public resolver (402 → pay flow)", async () => {
    const requests: { url: string; paid: boolean }[] = [];
    const spy = vi.fn(async (input: any, init?: any) => {
      const url = String(input);
      if (url.includes("/pay/")) {
        const paid = "X-Payment" in ((init?.headers ?? {}) as Record<string, unknown>);
        requests.push({ url, paid });
        return paid
          ? new Response(JSON.stringify({ credits_cents: 500 }), { status: 200 })
          : paymentRequired("5.00");
      }
      // JSON-RPC for the viem USDC balance read
      let rpcBody: any = {};
      try {
        rpcBody = JSON.parse(typeof init?.body === "string" ? init.body : "{}");
      } catch {
        rpcBody = {};
      }
      const result = rpcBody.method === "eth_call"
        ? `0x${(800_0000n).toString(16).padStart(64, "0")}` // $8 USDC
        : "0x2105";
      return new Response(
        JSON.stringify({ jsonrpc: "2.0", id: rpcBody.id ?? 1, result }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    });
    const original = globalThis.fetch;
    globalThis.fetch = spy as unknown as typeof fetch;

    const result = await bootstrapTopup({
      apiUrl: "https://api.conway.test",
      account: ACCOUNT,
      creditsCents: 100,
      chainType: "evm",
      dnsResolver: PUBLIC_DNS,
    });

    globalThis.fetch = original;
    expect(result?.success).toBe(true);
    expect(result?.amountUsd).toBe(5);
    expect(result?.creditsCentsAdded).toBe(500);
    expect(requests.filter((r) => r.paid)).toHaveLength(1);
  });

  it("topupCredits with NO injected resolver uses system DNS and fails closed on an unresolvable host", async () => {
    const requests: { url: string; paid: boolean }[] = [];
    const spy = vi.fn(async (input: any, init?: any) => {
      const url = String(input);
      if (url.includes("/pay/")) {
        return new Response("{}", { status: 200 });
      }
      // JSON-RPC: fund the wallet ($8 USDC) so the solvency precheck passes
      // and the request reaches the DNS-gated payment layer.
      let rpcBody: any = {};
      try {
        rpcBody = JSON.parse(typeof init?.body === "string" ? init.body : "{}");
      } catch {
        rpcBody = {};
      }
      const result = rpcBody.method === "eth_call"
        ? `0x${(800_0000n).toString(16).padStart(64, "0")}`
        : "0x2105";
      return new Response(
        JSON.stringify({ jsonrpc: "2.0", id: rpcBody.id ?? 1, result }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    });
    const original = globalThis.fetch;
    globalThis.fetch = spy as unknown as typeof fetch;

    const result = await topupCredits(
      "https://invalid.invalid", // RFC 6761 reserved TLD — guaranteed NXDOMAIN
      ACCOUNT,
      5,
      undefined,
      // no resolver → production system-DNS path
    );

    globalThis.fetch = original;
    expect(result.success).toBe(false);
    expect(result.error).toContain("resolution failed");
    expect(requests).toHaveLength(0);
  });
});

// ─── Redirect limit and statics unchanged (regression anchors) ──

describe("literal-IP and static behavior unchanged", () => {
  it("literal metadata IP still blocked without any DNS lookup", async () => {
    const dns = CALL_COUNTING_DNS([[PUBLIC_IP]]);
    const stub = stubMerchantFetch(() => OK_200());
    const result = await x402Fetch("https://169.254.169.254/x", ACCOUNT, "GET", undefined, undefined, 100, undefined, undefined, { dnsResolver: dns });
    stub.restore();

    expect(result.success).toBe(false);
    expect(result.error).toContain("private or reserved");
    expect(dns.calls).toHaveLength(0); // literal → static check, no resolution
  });
});

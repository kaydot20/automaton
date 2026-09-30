/**
 * M1-B4 — Outbound Network Policy (F4.1/F4.2/F4.3) — Regression Tests
 *
 * Covered (M1-A §F4.3 mandated test set):
 * - IP blocklist matrix (v4 + v6, private/reserved/loopback/link-local/
 *   CGNAT/ULA/multicast/mapped)
 * - Rebinding simulation: resolver returns public then private → denied
 * - Redirect-to-private blocked through ResilientHttpClient (manual hops)
 * - x402 to metadata IP blocked pre-signature (no fetch, no signature)
 * - Allowlist/host bypass attempts: unicode host, trailing dot, %2e
 * - IPFS CID validation
 * - No-side-effect guarantees: policy denial happens before any fetch
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  assertOutboundAllowed,
  isPrivateAddress,
  isLiteralPrivateHost,
  isHostnameWellFormed,
  isValidIpfsCid,
  type DnsResolver,
} from "../net/policy.js";
import { ResilientHttpClient } from "../conway/http-client.js";
import { isAllowedUri } from "../registry/discovery.js";
import { x402Fetch } from "../conway/x402.js";
import { privateKeyToAccount } from "viem/accounts";

const ACCOUNT = privateKeyToAccount(`0x${"22".repeat(32)}`);

// ─── IP blocklist matrix ────────────────────────────────────────

describe("isPrivateAddress — blocklist matrix", () => {
  const blocked = [
    "127.0.0.1",
    "127.255.255.254",
    "10.0.0.1",
    "10.255.255.255",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254", // cloud metadata
    "100.64.0.1", // CGNAT
    "100.127.255.255", // CGNAT top
    "0.0.0.0",
    "0.1.2.3",
    "192.0.2.1", // TEST-NET-1
    "198.51.100.7", // TEST-NET-2
    "203.0.113.9", // TEST-NET-3
    "198.18.0.5", // benchmarking
    "224.0.0.1", // multicast
    "239.255.255.255", // multicast
    "240.0.0.1", // reserved
    "255.255.255.255", // broadcast
    "::1",
    "::",
    "fe80::1",
    "febf::1",
    "fc00::1",
    "fd12:3456::1",
    "ff02::1",
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
    "::ffff:169.254.169.254",
  ];

  for (const ip of blocked) {
    it(`blocks ${ip}`, () => {
      expect(isPrivateAddress(ip)).toBe(true);
    });
  }

  const allowed = [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "172.15.255.255", // just below RFC1918
    "172.32.0.1", // just above RFC1918
    "100.63.255.255", // just below CGNAT
    "100.128.0.1", // just above CGNAT
    "2606:4700::1111",
    "2001:4860:4860::8888",
  ];

  for (const ip of allowed) {
    it(`allows ${ip}`, () => {
      expect(isPrivateAddress(ip)).toBe(false);
    });
  }
});

describe("literal hostname classification", () => {
  it("classifies localhost and private IP literals", () => {
    expect(isLiteralPrivateHost("localhost")).toBe(true);
    expect(isLiteralPrivateHost("LOCALHOST")).toBe(true);
    expect(isLiteralPrivateHost("sub.localhost")).toBe(true);
    expect(isLiteralPrivateHost("127.0.0.1")).toBe(true);
    expect(isLiteralPrivateHost("169.254.169.254")).toBe(true);
    expect(isLiteralPrivateHost("::1")).toBe(true);
    expect(isLiteralPrivateHost("example.com")).toBe(false);
    expect(isLiteralPrivateHost("8.8.8.8")).toBe(false);
  });

  it("flags malformed hostnames (bypass spellings)", () => {
    expect(isHostnameWellFormed("example.com")).toBe(true);
    expect(isHostnameWellFormed("sub.example.com")).toBe(true);
    expect(isHostnameWellFormed("xn--e1afmkfd.example.com")).toBe(true);
    expect(isHostnameWellFormed("exam\u0069le.com")).toBe(true); // ascii ok
    expect(isHostnameWellFormed("ex\u00e4mple.com")).toBe(false); // unicode
    expect(isHostnameWellFormed("exam_ple.com")).toBe(false); // underscore
    expect(isHostnameWellFormed("exam%2eple.com")).toBe(false); // percent
    expect(isHostnameWellFormed("")).toBe(false);
  });
});

// ─── URL-level gate: statics + DNS + purpose ────────────────────

describe("assertOutboundAllowed", () => {
  const publicResolver: DnsResolver = {
    lookup: async () => ["93.184.216.34"],
  };

  it("denies invalid URLs", async () => {
    expect((await assertOutboundAllowed("not-a-url", { purpose: "fetch" })).allowed).toBe(false);
  });

  it("denies non-https schemes", async () => {
    const r = await assertOutboundAllowed("http://example.com/x", { purpose: "fetch" });
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.code).toBe("SCHEME_NOT_ALLOWED");
  });

  it("http loopback is allowed only under the explicit dev flag", async () => {
    const withFlag = await assertOutboundAllowed("http://localhost:11434/api", {
      purpose: "fetch",
      allowHttpOnLoopback: true,
    });
    expect(withFlag.allowed).toBe(true);

    const withoutFlag = await assertOutboundAllowed("http://localhost:11434/api", {
      purpose: "fetch",
    });
    expect(withoutFlag.allowed).toBe(false);
    if (!withoutFlag.allowed) expect(withoutFlag.code).toBe("SCHEME_NOT_ALLOWED");

    // Dev flag does NOT extend to non-loopback hosts
    const remoteHttp = await assertOutboundAllowed("http://example.com/x", {
      purpose: "fetch",
      allowHttpOnLoopback: true,
      resolver: publicResolver,
    });
    expect(remoteHttp.allowed).toBe(false);
    if (!remoteHttp.allowed) expect(remoteHttp.code).toBe("SCHEME_NOT_ALLOWED");
  });

  it("denies literal private/metadata addresses", async () => {
    for (const url of [
      "https://169.254.169.254/latest/meta-data/",
      "https://127.0.0.1/admin",
      "https://10.0.0.5/internal",
      "https://192.168.1.1/router",
      "https://[::1]:8080/",
    ]) {
      const r = await assertOutboundAllowed(url, { purpose: "fetch" });
      expect(r.allowed).toBe(false);
      if (!r.allowed) expect(r.code).toBe("PRIVATE_ADDRESS");
    }
  });

  it("denies malformed hostname bypass spellings", async () => {
    for (const host of ["ex%E4mple.com", "exam_ple.com"]) {
      const r = await assertOutboundAllowed(`https://${host}/x`, { purpose: "fetch" });
      expect(r.allowed).toBe(false);
      if (!r.allowed) expect(r.code).toBe("INVALID_URL");
    }
  });

  it("trailing dot still resolves and applies the same checks", async () => {
    const r = await assertOutboundAllowed("https://169.254.169.254./x", { purpose: "fetch" });
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.code).toBe("PRIVATE_ADDRESS");
  });

  it("resolves DNS and blocks private results (rebinding capture)", async () => {
    const r = await assertOutboundAllowed("https://rebind.example.com/x", {
      purpose: "fetch",
      resolver: { lookup: async () => ["169.254.169.254"] },
    });
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.code).toBe("PRIVATE_ADDRESS");
  });

  it("validates EVERY resolved address, not just the first (multi-A rebinding)", async () => {
    const r = await assertOutboundAllowed("https://multi.example.com/x", {
      purpose: "fetch",
      resolver: { lookup: async () => ["93.184.216.34", "10.0.0.9"] },
    });
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.code).toBe("PRIVATE_ADDRESS");
  });

  it("resolves public hostnames to allowed", async () => {
    const r = await assertOutboundAllowed("https://api.conway.tech/v1/x", {
      purpose: "fetch",
      resolver: publicResolver,
    });
    expect(r.allowed).toBe(true);
  });

  it("payment purpose without allowlist denies (fail-closed), with allowlist enforces suffix rules", async () => {
    const denied = await assertOutboundAllowed("https://api.conway.tech/pay", {
      purpose: "payment",
      resolver: publicResolver,
    });
    expect(denied.allowed).toBe(false);

    const allowed = await assertOutboundAllowed("https://api.conway.tech/pay", {
      purpose: "payment",
      allowedDomains: ["conway.tech"],
      resolver: publicResolver,
    });
    expect(allowed.allowed).toBe(true);

    const suffixAttack = await assertOutboundAllowed("https://conway.tech.evil.com/pay", {
      purpose: "payment",
      allowedDomains: ["conway.tech"],
      resolver: { lookup: async () => ["93.184.216.34"] },
    });
    expect(suffixAttack.allowed).toBe(false);
  });
});

// ─── Client integration: redirects re-validated per hop ─────────

describe("ResilientHttpClient redirect re-validation (F4.3)", () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("blocks redirect-to-private before the second fetch", async () => {
    const client = new ResilientHttpClient({ maxRetries: 0 });
    const fetchSpy = vi.fn(async (url: any) => {
      const u = String(url);
      if (u.includes("public.example.com")) {
        return new Response(null, {
          status: 302,
          headers: { location: "https://169.254.169.254/latest/meta-data/" },
        });
      }
      return new Response("should not be reached", { status: 200 });
    });
    globalThis.fetch = fetchSpy as unknown as typeof fetch;

    await expect(
      client.request("https://public.example.com/start"),
    ).rejects.toThrow(/private or reserved/);

    expect(fetchSpy).toHaveBeenCalledTimes(1); // redirect hop never fetched
  });

  it("follows up to 3 safe redirects and arrives", async () => {
    const client = new ResilientHttpClient({ maxRetries: 0 });
    const urls: string[] = [];
    const fetchSpy = vi.fn(async (url: any) => {
      const u = String(url);
      urls.push(u);
      const n = u.match(/hop(\d+)/)?.[1];
      const idx = Number(n ?? 0);
      // hop0→hop1→hop2→hop3 = exactly 3 redirects; hop3 returns 200
      if (idx < 3) {
        return new Response(null, {
          status: 302,
          headers: { location: `https://public.example.com/hop${idx + 1}` },
        });
      }
      return new Response("arrived", { status: 200 });
    });
    globalThis.fetch = fetchSpy as unknown as typeof fetch;

    const resp = await client.request("https://public.example.com/hop0");
    expect(resp.status).toBe(200);
    expect(urls).toHaveLength(4); // hop0..hop3
  });

  it("denies the redirect past the 3-hop limit", async () => {
    const client = new ResilientHttpClient({ maxRetries: 0 });
    const urls: string[] = [];
    const fetchSpy = vi.fn(async (url: any) => {
      const u = String(url);
      urls.push(u);
      const n = u.match(/hop(\d+)/)?.[1];
      const idx = Number(n ?? 0);
      // Every hop redirects: hop0→hop1→hop2→hop3→hop4 (4 redirects total)
      if (idx < 4) {
        return new Response(null, {
          status: 302,
          headers: { location: `https://public.example.com/hop${idx + 1}` },
        });
      }
      return new Response("arrived", { status: 200 });
    });
    globalThis.fetch = fetchSpy as unknown as typeof fetch;

    await expect(client.request("https://public.example.com/hop0")).rejects.toThrow(
      /exceeded 3 redirects/,
    );
    expect(urls).toHaveLength(4); // never fetched hop4
  });

  it("returns 3xx responses without a Location header as-is", async () => {
    const client = new ResilientHttpClient({ maxRetries: 0 });
    // 304 must carry the original request headers per fetch spec, so use a
    // 302-shaped response with an empty location instead.
    globalThis.fetch = vi.fn(async () =>
      new Response("no location", {
        status: 302,
        headers: { location: "" },
      }),
    ) as unknown as typeof fetch;
    const resp = await client.request("https://public.example.com/x");
    expect(resp.status).toBe(302);
  });
});

// ─── x402 payment path: gate runs pre-signature ─────────────────

describe("x402 SSRF gate (F4.1)", () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("blocks x402 to the cloud metadata endpoint BEFORE any fetch or signature", async () => {
    const fetchSpy = vi.fn();
    globalThis.fetch = fetchSpy as unknown as typeof fetch;

    const result = await x402Fetch(
      "https://169.254.169.254/latest/meta-data/",
      ACCOUNT,
      "GET",
    );

    expect(result.success).toBe(false);
    expect(result.error).toContain("Blocked outbound request");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("blocks malformed-host x402 targets pre-signature", async () => {
    const fetchSpy = vi.fn();
    globalThis.fetch = fetchSpy as unknown as typeof fetch;

    const result = await x402Fetch("https://exam_ple.com/pay", ACCOUNT, "GET");

    expect(result.success).toBe(false);
    expect(result.error).toContain("Blocked outbound request");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("payment allowlist passed by the tool layer blocks non-allowlisted hosts", async () => {
    const fetchSpy = vi.fn();
    globalThis.fetch = fetchSpy as unknown as typeof fetch;

    const result = await x402Fetch(
      "https://pay.evil.test/api",
      ACCOUNT,
      "GET",
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      { allowedDomains: ["conway.tech"] },
    );

    expect(result.success).toBe(false);
    expect(result.error).toContain("not allowed for payment");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("topup path (no allowlist supplied) is not blocked by policy for a public host", async () => {
    // x402Fetch with no options: statics run, no payment allowlist. A public
    // hostname passes the precheck (DNS tier not configured here).
    globalThis.fetch = vi.fn(async () =>
      new Response(JSON.stringify({ error: "bad request" }), { status: 400 }),
    ) as unknown as typeof fetch;

    const result = await x402Fetch("https://api.conway.tech/pay/5/0xabc", ACCOUNT, "GET");
    // Not policy-blocked (error is from the HTTP 400 flow, not the policy gate)
    expect(result.error ?? "").not.toContain("Blocked outbound request");
  });
});

// ─── Discovery: IPFS CID validation + isAllowedUri compat ───────

describe("IPFS CID validation (F4.2)", () => {
  it("accepts only [a-zA-Z0-9]+ CIDs", () => {
    expect(isValidIpfsCid("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")).toBe(true);
    expect(isValidIpfsCid("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")).toBe(true);
    expect(isValidIpfsCid("../../etc/passwd")).toBe(false);
    expect(isValidIpfsCid("abc?x=1")).toBe(false);
    expect(isValidIpfsCid("a/b")).toBe(false);
    expect(isValidIpfsCid("")).toBe(false);
  });

  it("existing isAllowedUri behavior is preserved", () => {
    expect(isAllowedUri("https://example.com/card.json")).toBe(true);
    expect(isAllowedUri("http://example.com/card.json")).toBe(false);
    expect(isAllowedUri("https://localhost/card.json")).toBe(false);
    expect(isAllowedUri("ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")).toBe(true);
  });
});

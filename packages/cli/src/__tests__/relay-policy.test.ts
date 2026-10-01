/**
 * B4.1 (F4.2 remediation) — CLI relay policy regression tests.
 *
 * Proves the CLI send/fund relay paths enforce the shared outbound policy
 * (src/net/policy.ts — the single SSRF enforcement point) BEFORE any
 * signing, payload construction, or network transmission:
 *   - public HTTPS relays are allowed (legitimate behavior preserved)
 *   - literal private/metadata IPs denied before fetch
 *   - hostnames resolving to private addresses denied before fetch
 *   - mixed public/private DNS results denied
 *   - DNS failure / empty / malformed responses denied fail-closed
 *   - malformed-hostname bypass spellings (unicode, percent, underscores,
 *     multiple trailing dots) denied
 *   - insecure schemes denied
 *   - redirects to private destinations denied BEFORE the redirected fetch
 *   - no request / signature / transfer side effect occurs after denial
 *
 * Fully deterministic: every DNS answer is injected, every HTTP response
 * is stubbed or replaced. No test touches the real network.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { privateKeyToAccount } from "viem/accounts";

import {
  assertRelayUrlAllowed,
  relayFetch,
  type DnsResolver,
} from "../lib/relay-fetch.js";
import { isHostnameWellFormed } from "@conway/automaton/net/policy.js";
import { sendCommand, type SendDeps } from "../commands/send.js";
import { fundCommand, type FundDeps } from "../commands/fund.js";

const PUBLIC_IP = "93.184.216.34";
const PUBLIC_IP_2 = "104.18.32.7";
const PRIVATE_IP = "10.0.0.5";
const METADATA_IP = "169.254.169.254";

const allowAll: DnsResolver = { lookup: async () => [PUBLIC_IP] };

function denyAll(): DnsResolver {
  return { lookup: async () => { throw new Error("EAI_AGAIN"); } };
}

function okResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function redirectResponse(location: string, status = 302): Response {
  return new Response(null, { status, headers: { Location: location } });
}

/** Stub global fetch and return the recorder of attempted requests. */
function stubFetch(): { calls: Array<{ url: string; init?: RequestInit }> } {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const impl = async (url: any, init?: RequestInit) => {
    calls.push({ url: String(url), init });
    return okResponse({ ok: true });
  };
  vi.stubGlobal("fetch", vi.fn(impl));
  return { calls };
}

let tmpHome: string;

beforeEach(() => {
  tmpHome = mkdtempSync(join(tmpdir(), "b41-cli-"));
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  rmSync(tmpHome, { recursive: true, force: true });
});

describe("relay transport: assertRelayUrlAllowed", () => {
  it("allows a public HTTPS relay with resolvable public DNS", async () => {
    const guard = await assertRelayUrlAllowed(
      "https://social.conway.tech/v1/messages",
      allowAll,
    );
    expect(guard).toEqual({ allowed: true });
  });

  it("denies a literal metadata IP before any resolution", async () => {
    const guard = await assertRelayUrlAllowed(
      `https://${METADATA_IP}/v1/messages`,
      allowAll,
    );
    expect(guard.allowed).toBe(false);
    if (!guard.allowed) expect(guard.code).toBe("PRIVATE_ADDRESS");
  });

  it("denies a literal loopback IP", async () => {
    const guard = await assertRelayUrlAllowed(
      "https://127.0.0.1/v1/messages",
      allowAll,
    );
    expect(guard.allowed).toBe(false);
  });

  it("denies a hostname that resolves to a private address", async () => {
    const resolver: DnsResolver = { lookup: async () => [PRIVATE_IP] };
    const guard = await assertRelayUrlAllowed(
      "https://relay.example/v1/messages",
      resolver,
    );
    expect(guard.allowed).toBe(false);
    if (!guard.allowed) expect(guard.code).toBe("PRIVATE_ADDRESS");
  });

  it("denies when DNS returns a MIX of public and private addresses", async () => {
    const resolver: DnsResolver = {
      lookup: async () => [PUBLIC_IP, PRIVATE_IP],
    };
    const guard = await assertRelayUrlAllowed(
      "https://relay.example/v1/messages",
      resolver,
    );
    expect(guard.allowed).toBe(false);
    if (!guard.allowed) expect(guard.code).toBe("PRIVATE_ADDRESS");
  });

  it("denies fail-closed when DNS resolution throws", async () => {
    const guard = await assertRelayUrlAllowed(
      "https://relay.example/v1/messages",
      denyAll(),
    );
    expect(guard.allowed).toBe(false);
    if (!guard.allowed) expect(guard.code).toBe("RESOLUTION_FAILED");
  });

  it("denies fail-closed when DNS resolves to no addresses", async () => {
    const resolver: DnsResolver = { lookup: async () => [] };
    const guard = await assertRelayUrlAllowed(
      "https://relay.example/v1/messages",
      resolver,
    );
    expect(guard.allowed).toBe(false);
    if (!guard.allowed) expect(guard.code).toBe("RESOLUTION_FAILED");
  });

  it("denies fail-closed when the resolver returns a malformed address", async () => {
    const resolver: DnsResolver = { lookup: async () => ["not-an-ip"] };
    const guard = await assertRelayUrlAllowed(
      "https://relay.example/v1/messages",
      resolver,
    );
    expect(guard.allowed).toBe(false);
    if (!guard.allowed) expect(guard.code).toBe("RESOLUTION_FAILED");
  });

  it("denies raw unicode hostname labels at the policy layer", () => {
    // WHATWG URL parsing punycodes unicode labels before the policy sees
    // them, so the raw-label well-formedness check is asserted directly on
    // the shared policy function (same enforcement, deterministic).
    expect(isHostnameWellFormed("ex\u00e4mple.com")).toBe(false);
    expect(isHostnameWellFormed("xn--exmple-cua.com")).toBe(true);
  });

  it("denies percent-encoded hostname bypass spellings", async () => {
    // %5F decodes to "_" at the URL layer; the well-formedness check must
    // reject it so percent-decoded spellings cannot smuggle a bypass.
    const guard = await assertRelayUrlAllowed(
      "https://relay%5Fexample.com/v1/messages",
      allowAll,
    );
    expect(guard.allowed).toBe(false);
  });

  it("denies underscore hostname bypass spellings", async () => {
    const guard = await assertRelayUrlAllowed(
      "https://re_lay.example.com/v1/messages",
      allowAll,
    );
    expect(guard.allowed).toBe(false);
  });

  it("denies multiple-trailing-dot hostname bypass spellings", async () => {
    const guard = await assertRelayUrlAllowed(
      "https://relay.example.com../v1/messages",
      allowAll,
    );
    expect(guard.allowed).toBe(false);
  });

  it("denies plain http: (no dev flag on relay paths)", async () => {
    const guard = await assertRelayUrlAllowed(
      "http://relay.example/v1/messages",
      allowAll,
    );
    expect(guard.allowed).toBe(false);
    if (!guard.allowed) expect(guard.code).toBe("SCHEME_NOT_ALLOWED");
  });
});

describe("relay transport: relayFetch", () => {
  it("transmits to a public HTTPS relay through policy-gated fetch", async () => {
    const { calls } = stubFetch();
    const outcome = await relayFetch("https://relay.example/v1/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hello: "world" }),
      timeoutMs: 5_000,
      dnsResolver: allowAll,
    });
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.status).toBe(200);
    expect(calls).toHaveLength(1);
  });

  it("never calls fetch when the initial URL is denied", async () => {
    const { calls } = stubFetch();
    const outcome = await relayFetch(`https://${METADATA_IP}/v1/messages`, {
      method: "POST",
      body: "{}",
      dnsResolver: allowAll,
    });
    expect(outcome.ok).toBe(false);
    expect(calls).toHaveLength(0);
  });

  it("denies a redirect to a private destination BEFORE the redirected fetch", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const impl = async (url: any) => {
      calls.push({ url: String(url) });
      if (calls.length === 1) {
        return redirectResponse(`https://${PRIVATE_IP}/steal`);
      }
      return okResponse({ leaked: true });
    };
    vi.stubGlobal("fetch", vi.fn(impl));

    const outcome = await relayFetch("https://relay.example/v1/messages", {
      dnsResolver: allowAll,
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.code).toBe("PRIVATE_ADDRESS");
    expect(calls).toHaveLength(1); // redirected fetch never transmitted
  });

  it("denies a redirect to an insecure scheme BEFORE the redirected fetch", async () => {
    const calls: Array<{ url: string }> = [];
    const impl = async (url: any) => {
      calls.push({ url: String(url) });
      if (calls.length === 1) return redirectResponse("http://relay.example/x");
      return okResponse({ ok: true });
    };
    vi.stubGlobal("fetch", vi.fn(impl));

    const outcome = await relayFetch("https://relay.example/v1/messages", {
      dnsResolver: allowAll,
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.code).toBe("SCHEME_NOT_ALLOWED");
    expect(calls).toHaveLength(1);
  });

  it("follows a legitimate redirect to a public HTTPS destination", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const impl = async (url: any, init?: RequestInit) => {
      calls.push({ url: String(url), init });
      if (calls.length === 1) {
        return redirectResponse("https://relay2.example/v1/messages");
      }
      return okResponse({ ok: true });
    };
    vi.stubGlobal("fetch", vi.fn(impl));

    const outcome = await relayFetch("https://relay.example/v1/messages", {
      headers: { Authorization: "Bearer secret" },
      dnsResolver: allowAll,
    });
    expect(outcome.ok).toBe(true);
    expect(calls).toHaveLength(2);
  });

  it("converts 303 to GET without a body and drops cross-origin Authorization", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const impl = async (url: any, init?: RequestInit) => {
      calls.push({ url: String(url), init });
      if (calls.length === 1) {
        return redirectResponse("https://other.example/v1/messages", 303);
      }
      return okResponse({ ok: true });
    };
    vi.stubGlobal("fetch", vi.fn(impl));

    const outcome = await relayFetch("https://relay.example/v1/messages", {
      method: "POST",
      headers: { Authorization: "Bearer secret" },
      body: JSON.stringify({ a: 1 }),
      dnsResolver: allowAll,
    });
    expect(outcome.ok).toBe(true);
    expect(calls).toHaveLength(2);
    expect(calls[1].init?.method).toBe("GET");
    expect(calls[1].init?.body).toBeUndefined();
    expect((calls[1].init?.headers as any)?.Authorization).toBeUndefined();
  });

  it("enforces the redirect hop budget", async () => {
    const impl = async () => redirectResponse("https://relay.example/next");
    vi.stubGlobal("fetch", vi.fn(impl));

    const outcome = await relayFetch("https://relay.example/v1/messages", {
      maxRedirects: 2,
      dnsResolver: allowAll,
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.code).toBe("REDIRECT_LIMIT");
  });
});

describe("send command: policy enforcement before signing", () => {
  const baseDeps = (): SendDeps => ({
    loadConfig: () => ({ socialRelayUrl: "https://relay.example" }),
    dnsResolver: allowAll,
  });

  it("denies a private relay target and performs NO signing and NO request", async () => {
    const { calls } = stubFetch();
    const signMessage = vi.fn(async () => "0xsignature");
    const deps: SendDeps = {
      ...baseDeps(),
      loadConfig: () => ({ socialRelayUrl: `https://${METADATA_IP}` }),
      signMessage,
    };

    await expect(
      sendCommand("0xabc", "hello", deps),
    ).rejects.toThrow(/Blocked relay request \(PRIVATE_ADDRESS\)/);

    expect(signMessage).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
  });

  it("denies a hostname resolving private BEFORE signing the message", async () => {
    const { calls } = stubFetch();
    const signMessage = vi.fn(async () => "0xsignature");
    const deps: SendDeps = {
      ...baseDeps(),
      dnsResolver: { lookup: async () => [PRIVATE_IP] },
      signMessage,
    };

    await expect(
      sendCommand("0xabc", "hello", deps),
    ).rejects.toThrow(/Blocked relay request \(PRIVATE_ADDRESS\)/);

    expect(signMessage).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
  });

  it("denies fail-closed on DNS failure BEFORE signing the message", async () => {
    const { calls } = stubFetch();
    const signMessage = vi.fn(async () => "0xsignature");
    const deps: SendDeps = { ...baseDeps(), dnsResolver: denyAll(), signMessage };

    await expect(
      sendCommand("0xabc", "hello", deps),
    ).rejects.toThrow(/Blocked relay request \(RESOLUTION_FAILED\)/);

    expect(signMessage).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
  });

  it("sends a signed message through the guarded transport for a public relay", async () => {
    const { calls } = stubFetch();
    mkdirSync(join(tmpHome, ".automaton"), { recursive: true });
    const account = privateKeyToAccount(`0x${"01".repeat(32)}`);
    writeFileSync(
      join(tmpHome, ".automaton", "wallet.json"),
      JSON.stringify({ privateKey: `0x${"01".repeat(32)}` }),
    );
    vi.stubEnv("HOME", tmpHome);

    const deps: SendDeps = {
      ...baseDeps(),
      signMessage: async () => "0xsig",
    };

    const result = await sendCommand("0xabc", "hello", deps);
    expect(result.relayUrl).toBe("https://relay.example");
    expect(calls).toHaveLength(1);
    const body = JSON.parse(String(calls[0].init?.body));
    expect(body.signature).toBe("0xsig");
    expect(body.to).toBe("0xabc");
  });
});

describe("fund command: policy enforcement before transfer", () => {
  const baseDeps = (): FundDeps => ({
    loadConfig: () => ({
      name: "test",
      walletAddress: "0xwallet",
      conwayApiUrl: "https://api.example",
      conwayApiKey: "ck_test_12345678",
    }),
    dnsResolver: allowAll,
  });

  it("denies a private API target and transmits NO transfer request", async () => {
    const { calls } = stubFetch();
    const transport = vi.fn(async () => {
      throw new Error("transport must never be reached");
    });
    const deps: FundDeps = {
      ...baseDeps(),
      loadConfig: () => ({ ...baseDeps().loadConfig!(), conwayApiUrl: "https://10.0.0.9" }),
      relayFetchImpl: transport as any,
    };

    await expect(fundCommand("5.00", deps)).rejects.toThrow(
      /Blocked relay request \(PRIVATE_ADDRESS\)/,
    );
    expect(transport).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
  });

  it("denies a hostname resolving private BEFORE building/sending the payload", async () => {
    const { calls } = stubFetch();
    const transport = vi.fn(async () => {
      throw new Error("transport must never be reached");
    });
    const deps: FundDeps = {
      ...baseDeps(),
      dnsResolver: { lookup: async () => [PRIVATE_IP] },
      relayFetchImpl: transport as any,
    };

    await expect(fundCommand("5.00", deps)).rejects.toThrow(
      /Blocked relay request \(PRIVATE_ADDRESS\)/,
    );
    expect(transport).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
  });

  it("denies fail-closed on DNS failure — no transfer request, no fallback path", async () => {
    const { calls } = stubFetch();
    const transport = vi.fn(async () => {
      throw new Error("transport must never be reached");
    });
    const deps: FundDeps = {
      ...baseDeps(),
      dnsResolver: denyAll(),
      relayFetchImpl: transport as any,
    };

    await expect(fundCommand("5.00", deps)).rejects.toThrow(
      /Blocked relay request \(RESOLUTION_FAILED\)/,
    );
    expect(transport).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
  });

  it("submits a transfer through the guarded transport for a public API", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: any, init?: RequestInit) => {
        calls.push({ url: String(url), init });
        return okResponse({
          transfer_id: "t-123",
          status: "submitted",
          balance_after_cents: 500,
        });
      }),
    );

    const result = await fundCommand("5.00", baseDeps());
    expect(result.transferId).toBe("t-123");
    expect(result.amountCents).toBe(500);
    expect(result.destination).toBe("0xwallet");
    expect(result.maskedKey).toBe("ck_t...5678");
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("https://api.example/v1/credits/transfer");
    const headers = calls[0].init?.headers as Record<string, string>;
    expect(headers.Authorization).toBe("ck_test_12345678");
  });

  it("preserves the 404 endpoint-fallback behavior on the real transport", async () => {
    const calls: Array<{ url: string }> = [];
    const impl = async (url: any) => {
      calls.push({ url: String(url) });
      if (String(url).endsWith("/v1/credits/transfer")) {
        return new Response("not found", { status: 404 });
      }
      return okResponse({ transfer_id: "t-2", status: "submitted" });
    };
    vi.stubGlobal("fetch", vi.fn(impl));

    const result = await fundCommand("5.00", baseDeps());
    expect(result.transferId).toBe("t-2");
    expect(calls).toHaveLength(2);
    expect(calls[1].url.endsWith("/v1/credits/transfers")).toBe(true);
  });
});

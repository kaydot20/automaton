/**
 * B4.1 (F4.2 remediation) — Guarded CLI relay transport.
 *
 * The ONLY raw fetch() call site in the CLI. Every request — the initial
 * one and every redirect hop — is validated through the shared outbound
 * policy (src/net/policy.ts, the single SSRF enforcement point from
 * M1-B4/F4.3). No second SSRF implementation lives here.
 *
 * Enforced on every hop:
 *   1. scheme: https: only (http: never, relay paths have no dev flag)
 *   2. literal private/reserved host deny (IPs, localhost, IPv6 ULA)
 *   3. hostname well-formedness (unicode/underscore/percent bypass deny)
 *   4. MANDATORY DNS tier (requireDnsResolution: true): the hostname is
 *      resolved and EVERY returned address is validated against the
 *      private/reserved blocklist; resolution failure, empty results, and
 *      malformed addresses deny the request fail-closed
 *   5. redirects: followed manually with a hard budget (default 3), each
 *      Location fully re-validated BEFORE the redirected fetch; 303
 *      converts to GET without a body; a cross-origin redirect drops the
 *      Authorization header
 *
 * CLI relays use purpose "relay". The mandatory DNS tier is required
 * because relay URLs come from operator config/environment and must never
 * tunnel into private address space.
 */

import {
  assertOutboundAllowed,
  type DnsResolver,
} from "@conway/automaton/net/policy.js";

export type { DnsResolver };

export interface RelayFetchOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  /** DNS resolver override (tests inject a simulated resolver). */
  dnsResolver?: DnsResolver;
  /** Redirect hop budget (default 3, per F4.3). */
  maxRedirects?: number;
}

export type RelayGuard =
  | { allowed: true }
  | { allowed: false; code: string; message: string };

export type RelayFetchOutcome =
  | { ok: true; status: number; text: string }
  | { ok: false; code: string; message: string; status?: number };

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function policyOptions(dnsResolver?: DnsResolver) {
  return {
    purpose: "relay" as const,
    requireDnsResolution: true,
    ...(dnsResolver ? { resolver: dnsResolver } : {}),
  };
}

/**
 * Validate a relay URL against the shared outbound policy without
 * transmitting anything. Callers use this to fail closed BEFORE any
 * signing, payload construction, or credential handling.
 */
export async function assertRelayUrlAllowed(
  url: string,
  dnsResolver?: DnsResolver,
): Promise<RelayGuard> {
  const check = await assertOutboundAllowed(url, policyOptions(dnsResolver));
  if (check.allowed) return { allowed: true };
  return { allowed: false, code: check.code, message: check.message };
}

/**
 * Policy-gated relay fetch with per-hop re-validation and manual redirect
 * control. Fails closed: a denied URL never reaches fetch().
 */
export async function relayFetch(
  rawUrl: string,
  options: RelayFetchOptions = {},
): Promise<RelayFetchOutcome> {
  const maxRedirects = options.maxRedirects ?? 3;
  let currentUrl = rawUrl;
  let method = options.method ?? "GET";
  let body = options.body;
  const headers: Record<string, string> = { ...(options.headers ?? {}) };

  for (let hop = 0; ; hop++) {
    // Fail closed BEFORE the redirected fetch on every hop.
    const guard = await assertOutboundAllowed(currentUrl, policyOptions(options.dnsResolver));
    if (!guard.allowed) {
      return { ok: false, code: guard.code, message: guard.message };
    }
    if (hop > maxRedirects) {
      return {
        ok: false,
        code: "REDIRECT_LIMIT",
        message: `Blocked outbound request: redirect limit (${maxRedirects}) exceeded`,
      };
    }

    let response: Response;
    try {
      response = await fetch(currentUrl, {
        method,
        headers,
        ...(body !== undefined ? { body } : {}),
        redirect: "manual",
        ...(options.timeoutMs ? { signal: AbortSignal.timeout(options.timeoutMs) } : {}),
      });
    } catch (err) {
      return {
        ok: false,
        code: "TRANSPORT_ERROR",
        message: err instanceof Error ? err.message : String(err),
      };
    }

    if (REDIRECT_STATUSES.has(response.status)) {
      const location = response.headers.get("location");
      if (!location) {
        return {
          ok: false,
          code: "REDIRECT_NO_LOCATION",
          message: `Blocked outbound request: ${response.status} redirect without Location`,
          status: response.status,
        };
      }
      let nextUrl: URL;
      try {
        nextUrl = new URL(location, currentUrl);
      } catch {
        return {
          ok: false,
          code: "INVALID_URL",
          message: "Blocked outbound request: redirect Location is not a valid URL",
        };
      }
      // Cross-origin redirect: strip credential-bearing headers.
      if (nextUrl.origin !== new URL(currentUrl).origin) {
        delete headers.Authorization;
      }
      // 303: convert to GET without a body.
      if (response.status === 303) {
        method = "GET";
        body = undefined;
        delete headers["Content-Type"];
      }
      currentUrl = nextUrl.toString();
      continue;
    }

    const text = await response.text();
    if (!response.ok) {
      return {
        ok: false,
        code: "HTTP_ERROR",
        message: `${response.status}: ${text}`,
        status: response.status,
      };
    }
    return { ok: true, status: response.status, text };
  }
}

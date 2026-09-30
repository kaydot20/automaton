/**
 * Resilient HTTP Client
 *
 * Shared HTTP client with timeouts, retries, jittered exponential backoff,
 * and circuit breaker for all outbound Conway API calls.
 *
 * Phase 1.3: Network Resilience (P1-8, P1-9)
 * M1-B4 (F4.3): every request — and every redirect hop — passes the
 * outbound-network policy (src/net/policy.ts) before its fetch. Redirects
 * are followed manually (max 3 hops) so no hop can bypass re-validation.
 */

import type { HttpClientConfig } from "../types.js";
import { DEFAULT_HTTP_CLIENT_CONFIG } from "../types.js";
import {
  assertOutboundAllowed,
  type DnsResolver,
  type OutboundPurpose,
} from "../net/policy.js";

const MAX_REDIRECTS = 3;

function isRedirectStatus(status: number): boolean {
  return (
    status === 301 || status === 302 || status === 303 || status === 307 || status === 308
  );
}

export class CircuitOpenError extends Error {
  constructor(public readonly resetAt: number) {
    super(
      `Circuit breaker is open until ${new Date(resetAt).toISOString()}`,
    );
    this.name = "CircuitOpenError";
  }
}

export class ResilientHttpClient {
  private consecutiveFailures = 0;
  private circuitOpenUntil = 0;
  private readonly config: HttpClientConfig;

  constructor(config?: Partial<HttpClientConfig>) {
    this.config = { ...DEFAULT_HTTP_CLIENT_CONFIG, ...config };
  }

  /**
   * Perform a policy-checked request with manual redirect following.
   * Every hop — the initial URL and up to 3 redirects — passes the
   * outbound-network policy before its fetch, so a redirect can never
   * bypass re-validation (F4.3). Static checks (scheme, literal private
   * addresses, malformed hostnames) always run; DNS resolution runs when
   * a resolver is configured on the client.
   */
  async request(
    url: string,
    options?: RequestInit & {
      timeout?: number;
      idempotencyKey?: string;
      retries?: number;
      /** Per-call DNS resolver override (tests / scoped enforcement). */
      dnsResolver?: DnsResolver;
      /** Per-call mandatory-DNS override. */
      requireDnsResolution?: boolean;
    },
  ): Promise<Response> {
    const opts = options ?? {};
    const timeout = opts.timeout ?? this.config.baseTimeout;
    const maxRetries = opts.retries ?? this.config.maxRetries;
    // Per-call DNS overrides win over client defaults; mandatory-DNS is
    // sticky (a per-call false cannot weaken a client that requires it).
    const dnsResolver = opts.dnsResolver ?? this.config.dnsResolver;
    const requireDnsResolution =
      opts.requireDnsResolution === true || this.config.requireDnsResolution === true;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      let currentUrl = url;
      let hops = 0;

      // ── Policy-checked hop loop (redirects followed manually) ──
      // EVERY hop — the initial URL and each redirect destination — is
      // re-validated (including fresh DNS resolution) before its fetch.
      for (;;) {
        const check = await assertOutboundAllowed(currentUrl, {
          purpose: this.config.outboundPurpose ?? "fetch",
          allowedDomains: this.config.allowedDomains,
          allowHttpOnLoopback: this.config.allowHttpOnLoopback,
          resolver: dnsResolver,
          requireDnsResolution,
        });
        if (!check.allowed) {
          throw new Error(check.message);
        }

        if (this.isCircuitOpen()) {
          throw new CircuitOpenError(this.circuitOpenUntil);
        }

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeout);

        let response: Response;
        try {
          response = await fetch(currentUrl, {
            ...opts,
            redirect: "manual",
            signal: controller.signal,
            headers: {
              ...opts.headers,
              ...(opts.idempotencyKey
                ? { "Idempotency-Key": opts.idempotencyKey }
                : {}),
            },
          });
        } catch (error) {
          clearTimeout(timer);
          this.consecutiveFailures++;
          if (
            this.consecutiveFailures >= this.config.circuitBreakerThreshold
          ) {
            this.circuitOpenUntil =
              Date.now() + this.config.circuitBreakerResetMs;
          }
          if (attempt === maxRetries) throw error;
          await this.backoff(attempt);
          break; // next attempt restarts from the original URL
        }
        clearTimeout(timer);

        // Redirect handling: validate the target hop, follow manually.
        if (isRedirectStatus(response.status)) {
          if (hops >= MAX_REDIRECTS) {
            throw new Error(
              `Blocked outbound request: exceeded ${MAX_REDIRECTS} redirects`,
            );
          }
          const location = response.headers.get("location");
          if (location) {
            let nextUrl: string;
            try {
              nextUrl = new URL(location, currentUrl).toString();
            } catch {
              throw new Error(
                "Blocked outbound request: redirect location is not a valid URL",
              );
            }
            currentUrl = nextUrl;
            hops++;
            continue; // next hop passes through the policy gate above
          }
          // 3xx without a Location header: return as-is
        }

        // Count retryable HTTP errors toward circuit breaker, regardless of
        // whether we will actually retry. A server consistently returning 502
        // should eventually trip the circuit breaker.
        if (this.config.retryableStatuses.includes(response.status)) {
          this.consecutiveFailures++;
          if (this.consecutiveFailures >= this.config.circuitBreakerThreshold) {
            this.circuitOpenUntil = Date.now() + this.config.circuitBreakerResetMs;
          }
          if (attempt < maxRetries) {
            await this.backoff(attempt);
            break; // next attempt restarts from the original URL
          }
          return response;
        }

        // Only reset failure counter on truly successful responses
        this.consecutiveFailures = 0;
        return response;
      }
    }

    throw new Error("Unreachable");
  }

  private async backoff(attempt: number): Promise<void> {
    const delay = Math.min(
      this.config.backoffBase *
        Math.pow(2, attempt) *
        (0.5 + Math.random()),
      this.config.backoffMax,
    );
    await new Promise((resolve) => setTimeout(resolve, delay));
  }

  isCircuitOpen(): boolean {
    return Date.now() < this.circuitOpenUntil;
  }

  resetCircuit(): void {
    this.consecutiveFailures = 0;
    this.circuitOpenUntil = 0;
  }

  getConsecutiveFailures(): number {
    return this.consecutiveFailures;
  }

  /**
   * Direct access to the outbound-network policy for callers that need to
   * pre-check a URL before deciding to build a request at all.
   */
  async checkOutboundNetwork(
    url: string,
    purpose: OutboundPurpose,
    overrides?: { dnsResolver?: DnsResolver; requireDnsResolution?: boolean },
  ): Promise<void> {
    const check = await assertOutboundAllowed(url, {
      purpose,
      allowedDomains: this.config.allowedDomains,
      allowHttpOnLoopback: this.config.allowHttpOnLoopback,
      resolver: overrides?.dnsResolver ?? this.config.dnsResolver,
      requireDnsResolution:
        overrides?.requireDnsResolution === true ||
        this.config.requireDnsResolution === true,
    });
    if (!check.allowed) {
      throw new Error(check.message);
    }
  }
}

// Re-export for convenience so callers can inject resolvers without
// importing the policy module directly.
export type { DnsResolver };

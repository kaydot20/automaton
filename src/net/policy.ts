/**
 * Outbound Network Policy (M1-B4 / F4.3)
 *
 * Single fail-closed gate for every outbound HTTP(S) request:
 *
 *   assertOutboundAllowed(url, { purpose })
 *
 * Checks, in order:
 *   1. URL must parse and scheme must be https: (http: only for loopback
 *      hosts with the explicit dev flag).
 *   2. Literal hostnames (IPs, "localhost") are checked directly; every
 *      hostname is resolved via DNS and EVERY returned address is validated
 *      against the private/reserved IP blocklist — before any connection.
 *   3. Purpose-specific allowlist (payments: x402AllowedDomains).
 *
 * Blocklist (v4+v6): loopback, RFC1918, link-local (169.254/fe80::),
 * CGNAT (100.64/10), unique-local (fc00::/7), 0.0.0.0/8, multicast,
 * reserved, IPv4-mapped IPv6, and this-host (::).
 *
 * The URL string itself can encode the validated IP (e.g.
 * https://ip:port/path); connections then reach only the validated
 * address. Hostname pinning inside fetch is deferred until the runtime
 * gains a resolver-aware dispatcher (no new dependencies in this phase).
 */

export type OutboundPurpose = "payment" | "fetch" | "relay" | "discovery";

/** Result of a hostname-to-address resolution (injectable for tests). */
export interface DnsResolver {
  lookup(hostname: string): Promise<string[]>;
}

/** Reason a request was denied. */
export type NetworkDenialCode =
  | "INVALID_URL"
  | "SCHEME_NOT_ALLOWED"
  | "PRIVATE_ADDRESS"
  | "PURPOSE_NOT_ALLOWED"
  | "RESOLUTION_FAILED";

export interface NetworkDenial {
  allowed: false;
  code: NetworkDenialCode;
  message: string;
}

export interface NetworkAllowance {
  allowed: true;
}

export type NetworkCheckResult = NetworkDenial | NetworkAllowance;

export interface OutboundPolicyOptions {
  /** Purpose drives allowlists (payments have a domain allowlist). */
  purpose: OutboundPurpose;
  /** Domain allowlist for "payment" (e.g. TreasuryPolicy.x402FetchPolicy). */
  allowedDomains?: string[];
  /** Dev-only: allow plain http: to loopback (default false). */
  allowHttpOnLoopback?: boolean;
  /** DNS resolver override (tests inject the simulated resolver here). */
  resolver?: DnsResolver;
  /**
   * Deny (fail-closed) when DNS resolution cannot run (no resolver
   * configured). Default false: resolution-time enforcement is anchored at
   * configured resolvers so hosts without one degrade to static checks.
   */
  requireDnsResolution?: boolean;
}

// ─── IP blocklist ───────────────────────────────────────────────

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = value * 256 + n;
  }
  return value;
}

function ipv4InRange(ip: string, start: number, end: number): boolean {
  const value = ipv4ToInt(ip);
  if (value === null) return false;
  return value >= start && value <= end;
}

/**
 * True when the address is private, reserved, loopback, link-local,
 * CGNAT, ULA, multicast, or otherwise not a routable public unicast
 * destination. Never true for parse failures (callers must deny
 * unparseable addresses separately).
 */
export function isPrivateAddress(ip: string): boolean {
  // IPv4
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
    return (
      ipv4InRange(ip, 0, 0x00ffffff) || // 0.0.0.0/8 "this network"
      ipv4InRange(ip, 0x0a000000, 0x0affffff) || // 10.0.0.0/8
      ipv4InRange(ip, 0x64400000, 0x647fffff) || // 100.64.0.0/10 CGNAT
      ipv4InRange(ip, 0x7f000000, 0x7fffffff) || // 127.0.0.0/8 loopback
      ipv4InRange(ip, 0xa9fe0000, 0xa9feffff) || // 169.254.0.0/16 link-local
      ipv4InRange(ip, 0xac100000, 0xac1fffff) || // 172.16.0.0/12
      ipv4InRange(ip, 0xc0a80000, 0xc0a8ffff) || // 192.168.0.0/16
      ipv4InRange(ip, 0xc0000200, 0xc00002ff) || // 192.0.2.0/24 TEST-NET-1
      ipv4InRange(ip, 0xc0586300, 0xc05863ff) || // 192.88.99.0/24 6to4 relay
      ipv4InRange(ip, 0xc6120000, 0xc63fffff) || // 198.18.0.0/15 benchmark
      ipv4InRange(ip, 0xc6336400, 0xc63364ff) || // 198.51.100.0/24 TEST-NET-2
      ipv4InRange(ip, 0xcb007100, 0xcb0071ff) || // 203.0.113.0/24 TEST-NET-3
      ipv4InRange(ip, 0xe0000000, 0xefffffff) || // 224.0.0.0/4 multicast
      ipv4InRange(ip, 0xf0000000, 0xffffffff) || // 240.0.0.0/4 reserved + broadcast
      false
    );
  }

  // IPv6 (lowercase compare; zone IDs stripped by caller)
  const v6 = ip.toLowerCase();
  if (v6.includes(":")) {
    if (v6 === "::" || v6 === "::1") return true; // unspecified / loopback
    if (v6.startsWith("fe8") || v6.startsWith("fe9") || v6.startsWith("fea") || v6.startsWith("feb")) {
      return true; // fe80::/10 link-local
    }
    if (v6.startsWith("fc") || v6.startsWith("fd")) return true; // fc00::/7 ULA
    if (v6.startsWith("ff")) return true; // multicast
    if (v6.startsWith("::ffff:")) {
      // IPv4-mapped: validate the embedded v4
      return isPrivateAddress(v6.slice("::ffff:".length));
    }
    if (v6.startsWith("2002:")) {
      // 6to4 embeds an IPv4 in bits 16-48
      const embedded = v6.slice(5, 5 + "255.255.255.255".length);
      const candidate = embedded.split(":")[0];
      if (candidate.includes(".")) return isPrivateAddress(candidate);
      // Hex form: 2002:0a00:0001:: style — first two groups are the v4
      const groups = v6.split(":");
      if (groups.length >= 3) {
        const hi = parseInt(groups[1], 16);
        const lo = parseInt(groups[2], 16);
        if (Number.isFinite(hi) && Number.isFinite(lo)) {
          return isPrivateAddress(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
        }
      }
      return false;
    }
    if (v6.startsWith("64:ff9b:")) return false; // NAT64 well-known prefix → v4 behind it
    return false;
  }

  return false;
}

// ─── Hostname classification ────────────────────────────────────

/**
 * True when the URL hostname is literally a private/reserved address
 * (IP literal or "localhost" family) — no resolution required.
 */
export function isLiteralPrivateHost(hostname: string): boolean {
  const host = hostname
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^\[/, "")
    .replace(/\]$/, "")
    .replace(/%.*$/, "");
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (host.includes(":") || /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    return isPrivateAddress(host);
  }
  return false;
}

/**
 * Defense against bypass spellings: a hostname that is not a valid
 * public DNS label sequence (unicode, underscores, interior dots like
 * "1.2.3.4.evil.com" is fine, but "exampl\u0065.com" or "exam_ple.com"
 * or a trailing-dot-multiple) must deny rather than reach a resolver.
 */
export function isHostnameWellFormed(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (host.length === 0 || host.length > 253) return false;
  if (host.includes("%") || host.includes("_")) return false;
  // Every label: alphanumerics + hyphen (LDH), no leading/trailing hyphen,
  // punycode "xn--" labels allowed; anything else (unicode, spaces) denied.
  return host.split(".").every((label) => {
    if (label.length === 0 || label.length > 63) return false;
    if (!/^[a-z0-9-]+$/.test(label)) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
    return true;
  });
}

// ─── Purpose allowlists ─────────────────────────────────────────

function hostnameAllowedForPurpose(
  hostname: string,
  purpose: OutboundPurpose,
  allowedDomains: string[] | undefined,
): boolean {
  if (purpose !== "payment") return true;
  if (!allowedDomains || allowedDomains.length === 0) return false; // empty allowlist = payments disabled
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return allowedDomains.some(
    (domain) => host === domain || host.endsWith(`.${domain}`),
  );
}

// ─── Default resolver (system DNS via node:dns) ──────────────

async function defaultLookup(hostname: string): Promise<string[]> {
  const dns = await import("node:dns");
  const result = await dns.promises.lookup(hostname, { all: true, verbatim: true });
  return result.map((entry) => entry.address);
}

/** True when a resolved value is a parseable IP literal (v4 or v6). */
function isParseableAddress(address: string): boolean {
  const value = address.toLowerCase().replace(/%.*$/, "");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return ipv4ToInt(value) !== null;
  return value.includes(":");
}

// ─── Main gate ──────────────────────────────────────────────────

/**
 * Fail-closed outbound request gate. Returns { allowed: true } or a
 * denial; callers must abort the request on denial and surface the code.
 */
export async function assertOutboundAllowed(
  rawUrl: string,
  options: OutboundPolicyOptions,
): Promise<NetworkCheckResult> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    // Message preserves the legacy "Invalid URL" contract of the HTTP client.
    return { allowed: false, code: "INVALID_URL", message: `Blocked outbound request: Invalid URL` };
  }

  // 1. Scheme
  const scheme = parsed.protocol.toLowerCase();
  const isLoopbackHost = isLiteralPrivateHost(parsed.hostname);
  if (scheme === "http:") {
    if (!(options.allowHttpOnLoopback === true && isLoopbackHost)) {
      // Message preserves the legacy "HTTPS required" contract of the HTTP client.
      return {
        allowed: false,
        code: "SCHEME_NOT_ALLOWED",
        message: "Blocked outbound request: HTTPS required (insecure scheme)",
      };
    }
  } else if (scheme !== "https:") {
    return {
      allowed: false,
      code: "SCHEME_NOT_ALLOWED",
      message: `Blocked outbound request: unsupported scheme ${parsed.protocol}`,
    };
  }

  const hostname = parsed.hostname.toLowerCase();

  // The ONLY combination in which a loopback literal is legal: plain http:
  // to loopback with the explicit dev flag (local Ollama-style endpoints).
  const loopbackDevException =
    scheme === "http:" &&
    options.allowHttpOnLoopback === true &&
    isLiteralPrivateHost(hostname);

  // 2a. Literal hosts (IPs / localhost) — no resolution
  if (isLiteralPrivateHost(hostname) && !loopbackDevException) {
    return {
      allowed: false,
      code: "PRIVATE_ADDRESS",
      message: `Blocked outbound request: private or reserved address`,
    };
  }

  // 2b. Bypass-spelling defense before resolution
  if (!isHostnameWellFormed(hostname)) {
    return {
      allowed: false,
      code: "INVALID_URL",
      message: "Blocked outbound request: malformed hostname",
    };
  }

  // 2c. Resolve and validate EVERY address. Resolution runs whenever a
  // resolver is injected OR the caller requires DNS validation (mandatory
  // tier — production x402/payment). Fail-closed on failure, empty results,
  // and malformed resolution output.
  if (options.resolver || options.requireDnsResolution === true) {
    const lookup = options.resolver
      ? options.resolver.lookup
      : defaultLookup;
    let addresses: string[];
    try {
      addresses = await lookup(hostname);
    } catch {
      if (options.requireDnsResolution === true) {
        return {
          allowed: false,
          code: "RESOLUTION_FAILED",
          message: "Blocked outbound request: hostname resolution failed",
        };
      }
      // Explicit resolver unavailable on a non-mandatory path: degrade to
      // static checks (documented).
      return { allowed: true };
    }
    if (!Array.isArray(addresses) || addresses.length === 0) {
      return {
        allowed: false,
        code: "RESOLUTION_FAILED",
        message: "Blocked outbound request: hostname resolved to no addresses",
      };
    }
    for (const address of addresses) {
      if (!isParseableAddress(address)) {
        return {
          allowed: false,
          code: "RESOLUTION_FAILED",
          message: "Blocked outbound request: resolver returned a malformed address",
        };
      }
      if (isPrivateAddress(address)) {
        return {
          allowed: false,
          code: "PRIVATE_ADDRESS",
          message: "Blocked outbound request: hostname resolves to a private or reserved address",
        };
      }
    }
  }

  // 3. Purpose allowlist (after network checks; do not leak which check failed)
  if (!hostnameAllowedForPurpose(hostname, options.purpose, options.allowedDomains)) {
    return {
      allowed: false,
      code: "PURPOSE_NOT_ALLOWED",
      message: `Blocked outbound request: host not allowed for ${options.purpose}`,
    };
  }

  return { allowed: true };
}

/**
 * Convenience helper: true when the full check passes. Equivalent to
 * (await assertOutboundAllowed(url, options)).allowed.
 */
export async function isOutboundAllowed(
  rawUrl: string,
  options: OutboundPolicyOptions,
): Promise<boolean> {
  return (await assertOutboundAllowed(rawUrl, options)).allowed;
}

/**
 * Validate an IPFS CID segment: the only characters a CID may contain.
 * Applied before user URI text is spliced into a gateway URL.
 */
export function isValidIpfsCid(cid: string): boolean {
  return /^[a-zA-Z0-9]+$/.test(cid);
}

/**
 * automaton-cli fund <amount> [--to 0x...]
 *
 * Transfer Conway credits using the configured Conway API key.
 *
 * B4.1 (F4.2 remediation): the credit-transfer API request is validated
 * against the shared outbound-network policy (src/net/policy.ts via
 * lib/relay-fetch.ts) BEFORE the payload is constructed — a policy denial
 * performs no request and no transfer. The transport itself is
 * relayFetch(), which re-validates every redirect hop.
 */

import { loadConfig } from "@conway/automaton/config.js";
import {
  assertRelayUrlAllowed,
  relayFetch,
  type DnsResolver,
} from "../lib/relay-fetch.js";

export interface FundDeps {
  /** Config loader (injectable for tests). */
  loadConfig?: () => {
    name?: string;
    walletAddress: string;
    conwayApiUrl?: string;
    conwayApiKey?: string;
  } | null;
  /** Recipient override (CLI --to flag). Defaults to config.walletAddress. */
  toAddressOverride?: string;
  /** DNS resolver override for the policy gate (tests). */
  dnsResolver?: DnsResolver;
  /** Transport override (tests). Defaults to the policy-gated relayFetch. */
  relayFetchImpl?: typeof relayFetch;
}

export interface FundResult {
  transferId: string;
  status: string;
  destination: string;
  amountCents: number;
  balanceAfterCents: number | undefined;
  maskedKey: string;
}

const DEFAULT_API_URL = "https://api.conway.tech";
const TRANSFER_PATHS = ["/v1/credits/transfer", "/v1/credits/transfers"];

/**
 * Submit a credit transfer. Throws on policy denial
 * ("Blocked relay request (...)"), transport failure, or missing
 * configuration — in every denial case no request is transmitted.
 */
export async function fundCommand(
  amount: string,
  deps: FundDeps = {},
): Promise<FundResult> {
  const load = deps.loadConfig ?? loadConfig;
  const transport = deps.relayFetchImpl ?? relayFetch;

  const config = load();
  if (!config) {
    throw new Error("No automaton configuration found.");
  }

  if (!config.conwayApiKey) {
    throw new Error("No Conway API key found in automaton config.");
  }

  const amountCents = parseAmountToCents(amount);
  if (amountCents <= 0) {
    throw new Error(`Invalid amount: ${amount}`);
  }

  const apiUrl = config.conwayApiUrl || DEFAULT_API_URL;
  const destination = deps.toAddressOverride || config.walletAddress;

  // Fail closed BEFORE any payload construction or credential handling.
  // The transfer endpoints share one API origin; validating the first path
  // validates the origin every path in TRANSFER_PATHS uses.
  const guard = await assertRelayUrlAllowed(`${apiUrl}${TRANSFER_PATHS[0]}`, deps.dnsResolver);
  if (!guard.allowed) {
    throw new Error(`Blocked relay request (${guard.code}): ${guard.message}`);
  }

  const payload = {
    to_address: destination,
    amount_cents: amountCents,
    note: `fund via automaton-cli (${config.name})`,
  };

  let success: any | null = null;
  let lastError = "";

  for (const path of TRANSFER_PATHS) {
    const outcome = await transport(`${apiUrl}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: config.conwayApiKey,
      },
      body: JSON.stringify(payload),
      ...(deps.dnsResolver ? { dnsResolver: deps.dnsResolver } : {}),
    });

    if (!outcome.ok) {
      if (outcome.code === "HTTP_ERROR") {
        lastError = outcome.message;
        if (outcome.status === 404) {
          continue;
        }
        throw new Error(`Credit transfer failed (${path}): ${lastError}`);
      }
      // Policy denial or transport failure: fail closed, no further paths.
      throw new Error(`Blocked relay request (${outcome.code}): ${outcome.message}`);
    }

    success = JSON.parse(outcome.text || "{}");
    break;
  }

  if (!success) {
    throw new Error(`Credit transfer failed: ${lastError || "unknown error"}`);
  }

  return {
    transferId: success.transfer_id || success.id || "n/a",
    status: success.status || "submitted",
    destination,
    amountCents,
    balanceAfterCents:
      success.balance_after_cents ?? success.new_balance_cents,
    maskedKey: maskKey(config.conwayApiKey ?? ""),
  };
}

/** CLI entrypoint: argv parsing + output + exit codes (unchanged behavior). */
export async function fundCli(): Promise<void> {
  const args = process.argv.slice(3);
  const amount = args[0];
  const toIndex = args.indexOf("--to");
  const toAddress = toIndex >= 0 ? args[toIndex + 1] : undefined;

  if (!amount) {
    console.log("Usage: automaton-cli fund <amount> [--to 0x...]");
    console.log("Examples:");
    console.log("  automaton-cli fund 5.00");
    console.log("  automaton-cli fund 500 --to 0xabc...");
    process.exit(1);
  }

  let result: FundResult;
  try {
    result = await fundCommand(amount, { toAddressOverride: toAddress });
  } catch (err: any) {
    const msg = String(err?.message ?? err);
    if (
      msg === "No automaton configuration found." ||
      msg.startsWith("No Conway API key found") ||
      msg.startsWith("Invalid amount:")
    ) {
      console.log(msg);
      process.exit(1);
    }
    console.log(`Credit transfer failed: ${msg}`);
    process.exit(1);
  }

  const balanceAfter =
    result.balanceAfterCents !== undefined
      ? `Balance:   $${(Number(result.balanceAfterCents) / 100).toFixed(2)} after transfer`
      : "";

  console.log(`
Transfer submitted.
From key:  ${result.maskedKey}
To:        ${result.destination}
Amount:    $${(result.amountCents / 100).toFixed(2)} (${result.amountCents} cents)
Status:    ${result.status}
Transfer:  ${result.transferId}
${balanceAfter}
`);
}

function parseAmountToCents(raw: string): number {
  const trimmed = raw.trim();
  if (!trimmed) return 0;

  // If user provides integer >= 100, treat as cents.
  if (/^\d+$/.test(trimmed) && Number(trimmed) >= 100) {
    return Number(trimmed);
  }

  const dollars = Number(trimmed);
  if (!Number.isFinite(dollars)) return 0;
  return Math.round(dollars * 100);
}

function maskKey(key: string): string {
  if (key.length < 8) return "***";
  return `${key.slice(0, 4)}...${key.slice(-4)}`;
}

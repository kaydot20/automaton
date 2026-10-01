/**
 * automaton-cli send <to-address> "message text"
 *
 * Send a message to an automaton or address via the social relay.
 *
 * Phase 3.2: CRITICAL FIX (S-P0-1) — All outbound messages are now signed
 * using the same canonical format as the runtime client.
 *
 * B4.1 (F4.2 remediation): the relay request is validated against the
 * shared outbound-network policy (src/net/policy.ts via lib/relay-fetch.ts)
 * BEFORE the wallet is loaded or the message is signed — a policy denial
 * performs no signing and no network side effect. The transport itself is
 * relayFetch(), which re-validates every redirect hop.
 */

import { loadConfig } from "@conway/automaton/config.js";
import { privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";
import { keccak256, toBytes } from "viem";
import fs from "fs";
import path from "path";
import {
  assertRelayUrlAllowed,
  relayFetch,
  type DnsResolver,
} from "../lib/relay-fetch.js";

export interface SendDeps {
  /** Config loader (injectable for tests). */
  loadConfig?: () => { socialRelayUrl?: string } | null;
  /** Message signer (injectable for tests). */
  signMessage?: (account: PrivateKeyAccount, canonical: string) => Promise<string>;
  /** DNS resolver override for the policy gate (tests). */
  dnsResolver?: DnsResolver;
  /** Transport override (tests). Defaults to the policy-gated relayFetch. */
  relayFetchImpl?: typeof relayFetch;
}

export interface SendResult {
  id: string;
  from: string;
  to: string;
  relayUrl: string;
}

const DEFAULT_RELAY_URL = "https://social.conway.tech";

/**
 * Send a signed message via the social relay. Throws on policy denial
 * ("Blocked relay request (...)") or transport failure — before any error,
 * no signature has been produced and no request has been transmitted.
 */
export async function sendCommand(
  toAddress: string,
  messageText: string,
  deps: SendDeps = {},
): Promise<SendResult> {
  const load = deps.loadConfig ?? loadConfig;
  const signMessage = deps.signMessage ?? defaultSignMessage;
  const transport = deps.relayFetchImpl ?? relayFetch;

  const config = load();
  const relayUrl =
    config?.socialRelayUrl ||
    process.env.SOCIAL_RELAY_URL ||
    DEFAULT_RELAY_URL;

  // Fail closed BEFORE any signing or credential handling.
  const guard = await assertRelayUrlAllowed(`${relayUrl}/v1/messages`, deps.dnsResolver);
  if (!guard.allowed) {
    throw new Error(`Blocked relay request (${guard.code}): ${guard.message}`);
  }

  // Load wallet (only after the destination is policy-approved).
  const walletPath = path.join(
    process.env.HOME || "/root",
    ".automaton",
    "wallet.json",
  );

  if (!fs.existsSync(walletPath)) {
    throw new Error("No wallet found at ~/.automaton/wallet.json");
  }

  const walletData = JSON.parse(fs.readFileSync(walletPath, "utf-8"));
  const account: PrivateKeyAccount = privateKeyToAccount(walletData.privateKey as `0x${string}`);

  // Phase 3.2: Sign the message using the same canonical format as runtime
  // Canonical: Conway:send:{to_lowercase}:{keccak256(toBytes(content))}:{signed_at_iso}
  const signedAt = new Date().toISOString();
  const contentHash = keccak256(toBytes(messageText));
  const canonical = `Conway:send:${toAddress.toLowerCase()}:${contentHash}:${signedAt}`;
  const signature = await signMessage(account, canonical);

  const outcome = await transport(`${relayUrl}/v1/messages`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      from: account.address.toLowerCase(),
      to: toAddress.toLowerCase(),
      content: messageText,
      signed_at: signedAt,
      signature,
    }),
    timeoutMs: 30_000,
    ...(deps.dnsResolver ? { dnsResolver: deps.dnsResolver } : {}),
  });

  if (!outcome.ok) {
    if (outcome.code === "HTTP_ERROR") {
      throw new Error(`Relay returned ${outcome.message}`);
    }
    throw new Error(`Blocked relay request (${outcome.code}): ${outcome.message}`);
  }

  const result = JSON.parse(outcome.text || "{}") as { id?: string };
  return {
    id: result.id || "n/a",
    from: account.address,
    to: toAddress,
    relayUrl,
  };
}

function defaultSignMessage(
  account: PrivateKeyAccount,
  canonical: string,
): Promise<string> {
  return account.signMessage({ message: canonical });
}

/** CLI entrypoint: argv parsing + output + exit codes (unchanged behavior). */
export async function sendCli(): Promise<void> {
  const args = process.argv.slice(3);
  const toAddress = args[0];
  const messageText = args.slice(1).join(" ");

  if (!toAddress || !messageText) {
    console.log("Usage: automaton-cli send <to-address> <message>");
    console.log("Examples:");
    console.log('  automaton-cli send 0xabc...def "Hello, fellow automaton!"');
    process.exit(1);
  }

  try {
    const result = await sendCommand(toAddress, messageText);
    console.log(`Message sent (signed).`);
    console.log(`  ID:   ${result.id}`);
    console.log(`  From: ${result.from}`);
    console.log(`  To:   ${result.to}`);
    console.log(`  Relay: ${result.relayUrl}`);
  } catch (err: any) {
    if (err?.message?.startsWith("No wallet found")) {
      console.log(err.message);
      console.log("Run: automaton --init");
      process.exit(1);
    }
    console.error(`Failed to send message: ${err.message}`);
    process.exit(1);
  }
}

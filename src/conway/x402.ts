/**
 * x402 Payment Protocol
 *
 * Enables the automaton to make USDC micropayments via HTTP 402.
 * Adapted from conway-mcp/src/x402/index.ts
 */

import {
  createPublicClient,
  http,
  parseUnits,
  type Address,
  type PrivateKeyAccount,
} from "viem";
import { base, baseSepolia } from "viem/chains";
import { ResilientHttpClient } from "./http-client.js";
import { checkReserve, validateSpendCents } from "./reserve.js";
import { DEFAULT_TREASURY_POLICY } from "../types.js";
import type { ChainType } from "../identity/chain.js";

const x402HttpClient = new ResilientHttpClient();

// USDC contract addresses
const USDC_ADDRESSES: Record<string, Address> = {
  "eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // Base mainnet
  "eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e", // Base Sepolia
};

const CHAINS: Record<string, any> = {
  "eip155:8453": base,
  "eip155:84532": baseSepolia,
};
type NetworkId = keyof typeof USDC_ADDRESSES;

const BALANCE_OF_ABI = [
  {
    inputs: [{ name: "account", type: "address" }],
    name: "balanceOf",
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
    type: "function",
  },
] as const;

interface PaymentRequirement {
  scheme: string;
  network: NetworkId;
  maxAmountRequired: string;
  payToAddress: Address;
  requiredDeadlineSeconds: number;
  usdcAddress: Address;
}

interface PaymentRequiredResponse {
  x402Version: number;
  accepts: PaymentRequirement[];
}

interface ParsedPaymentRequirement {
  x402Version: number;
  requirement: PaymentRequirement;
}

interface X402PaymentResult {
  success: boolean;
  response?: any;
  error?: string;
  status?: number;
}

export interface UsdcBalanceResult {
  balance: number;
  network: string;
  ok: boolean;
  error?: string;
}

function safeJsonParse(value: string): unknown | null {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function parsePositiveInt(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    return Math.floor(value);
  }
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    if (Number.isFinite(parsed) && parsed > 0) {
      return Math.floor(parsed);
    }
  }
  return null;
}

function normalizeNetwork(raw: unknown): NetworkId | null {
  if (typeof raw !== "string") return null;
  const normalized = raw.trim().toLowerCase();
  if (normalized === "base") return "eip155:8453";
  if (normalized === "base-sepolia") return "eip155:84532";
  if (normalized === "eip155:8453" || normalized === "eip155:84532") {
    return normalized;
  }
  return null;
}

function normalizePaymentRequirement(raw: unknown): PaymentRequirement | null {
  if (typeof raw !== "object" || raw === null) return null;
  const value = raw as Record<string, unknown>;
  const network = normalizeNetwork(value.network);
  if (!network) return null;

  const scheme = typeof value.scheme === "string" ? value.scheme : null;
  const maxAmountRequired = typeof value.maxAmountRequired === "string"
    ? value.maxAmountRequired
    : typeof value.maxAmountRequired === "number" &&
        Number.isFinite(value.maxAmountRequired)
      ? String(value.maxAmountRequired)
      : null;
  const payToAddress = typeof value.payToAddress === "string"
    ? value.payToAddress
    : typeof value.payTo === "string"
      ? value.payTo
      : null;
  const usdcAddress = typeof value.usdcAddress === "string"
    ? value.usdcAddress
    : typeof value.asset === "string"
      ? value.asset
      : USDC_ADDRESSES[network];
  const requiredDeadlineSeconds =
    parsePositiveInt(value.requiredDeadlineSeconds) ??
    parsePositiveInt(value.maxTimeoutSeconds) ??
    300;

  if (!scheme || !maxAmountRequired || !payToAddress || !usdcAddress) {
    return null;
  }

  return {
    scheme,
    network,
    maxAmountRequired,
    payToAddress: payToAddress as Address,
    requiredDeadlineSeconds,
    usdcAddress: usdcAddress as Address,
  };
}

function normalizePaymentRequired(raw: unknown): PaymentRequiredResponse | null {
  if (typeof raw !== "object" || raw === null) return null;
  const value = raw as Record<string, unknown>;
  if (!Array.isArray(value.accepts)) return null;

  const accepts = value.accepts
    .map(normalizePaymentRequirement)
    .filter((v): v is PaymentRequirement => v !== null);
  if (!accepts.length) return null;

  const x402Version = parsePositiveInt(value.x402Version) ?? 1;
  return { x402Version, accepts };
}

export function parseMaxAmountRequired(maxAmountRequired: string, x402Version: number): bigint {
  const amount = maxAmountRequired.trim();
  if (!/^\d+(\.\d+)?$/.test(amount)) {
    throw new Error(`Invalid maxAmountRequired: ${maxAmountRequired}`);
  }

  if (amount.includes(".")) {
    return parseUnits(amount, 6);
  }
  if (x402Version >= 2 || amount.length > 6) {
    return BigInt(amount);
  }
  return parseUnits(amount, 6);
}

function selectRequirement(parsed: PaymentRequiredResponse): PaymentRequirement {
  const exactSupported = parsed.accepts.find(
    (r) => r.scheme === "exact" && !!CHAINS[r.network],
  );
  if (exactSupported) return exactSupported;
  return parsed.accepts[0];
}

/** Solana USDC mint address (mainnet). */
const SOLANA_USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/**
 * Get the raw USDC balance (atomic units, 6 decimals) for an address.
 * Throws on RPC failure — callers decide how to degrade.
 */
async function getUsdcBalanceAtomic(
  address: Address,
  network: string = "eip155:8453",
): Promise<bigint> {
  const chain = CHAINS[network];
  const usdcAddress = USDC_ADDRESSES[network];
  if (!chain || !usdcAddress) {
    throw new Error(`Unsupported USDC network: ${network}`);
  }

  const rpcUrl = process.env.AUTOMATON_RPC_URL || undefined;
  const client = createPublicClient({
    chain,
    transport: http(rpcUrl, { timeout: 10_000 }),
  });

  return await client.readContract({
    address: usdcAddress,
    abi: BALANCE_OF_ABI,
    functionName: "balanceOf",
    args: [address],
  });
}

/**
 * Get the USDC balance for the automaton's wallet on a given network.
 * Supports both EVM (Base) and Solana networks.
 */
export async function getUsdcBalance(
  address: string,
  network: string = "eip155:8453",
  chainType?: ChainType,
): Promise<number> {
  if (chainType === "solana" || network === "solana:mainnet") {
    return getSolanaUsdcBalance(address);
  }
  const result = await getUsdcBalanceDetailed(address as Address, network);
  return result.balance;
}

/**
 * Get the USDC balance on Solana using @solana/web3.js.
 */
async function getSolanaUsdcBalance(address: string): Promise<number> {
  try {
    const { Connection, PublicKey } = await import("@solana/web3.js");
    const rpcUrl = process.env.SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";
    const connection = new Connection(rpcUrl, "confirmed");
    const ownerPubkey = new PublicKey(address);
    const mintPubkey = new PublicKey(SOLANA_USDC_MINT);

    // Find associated token account for USDC
    const tokenAccounts = await connection.getParsedTokenAccountsByOwner(
      ownerPubkey,
      { mint: mintPubkey },
    );

    if (tokenAccounts.value.length === 0) {
      return 0;
    }

    // Sum all USDC token accounts (usually just one)
    let totalBalance = 0;
    for (const account of tokenAccounts.value) {
      const parsed = account.account.data.parsed;
      if (parsed?.info?.tokenAmount?.uiAmount != null) {
        totalBalance += parsed.info.tokenAmount.uiAmount;
      }
    }

    return totalBalance;
  } catch (err: any) {
    throw new Error(`Solana USDC balance check failed: ${err?.message || String(err)}`);
  }
}

/**
 * Get the USDC balance and read status details for diagnostics.
 */
export async function getUsdcBalanceDetailed(
  address: Address,
  network: string = "eip155:8453",
): Promise<UsdcBalanceResult> {
  try {
    const balanceAtomic = await getUsdcBalanceAtomic(address, network);
    // USDC has 6 decimals
    return {
      balance: Number(balanceAtomic) / 1_000_000,
      network,
      ok: true,
    };
  } catch (err: any) {
    return {
      balance: 0,
      network,
      ok: false,
      error: err?.message || String(err),
    };
  }
}

/**
 * Check if a URL requires x402 payment.
 */
export async function checkX402(
  url: string,
): Promise<PaymentRequirement | null> {
  try {
    const resp = await x402HttpClient.request(url, { method: "HEAD" });
    if (resp.status !== 402) {
      return null;
    }
    const parsed = await parsePaymentRequired(resp);
    return parsed?.requirement ?? null;
  } catch {
    return null;
  }
}

/**
 * Fetch a URL with automatic x402 payment.
 * If the endpoint returns 402, sign and pay, then retry.
 */
/**
 * Fetch a URL with automatic x402 payment.
 * If the endpoint returns 402, sign and pay, then retry.
 *
 * @param maxPaymentCents explicit per-payment cap in cents; a malformed
 *   value (non-finite/negative) falls back to the conservative treasury
 *   default rather than disabling the cap
 * @param skipReserveCheck INTERNAL: used only by the credit-topup income
 *   path (topupCredits), which enforces its own tier validation, solvency,
 *   and cross-recipient reserve checks. Topup converts USDC into credits —
 *   value does not leave the agent — so charging the USDC reserve against it
 *   would create a starvation lock. Never expose this through tool args.
 */
export async function x402Fetch(
  url: string,
  account: PrivateKeyAccount,
  method: string = "GET",
  body?: string,
  headers?: Record<string, string>,
  maxPaymentCents?: number,
  chainType?: ChainType,
  skipReserveCheck?: boolean,
): Promise<X402PaymentResult> {
  // Solana wallets cannot sign EVM x402 payments
  if (chainType === "solana") {
    return {
      success: false,
      error: "x402 payment requires an EVM wallet. Solana automatons should use Conway credits API instead.",
    };
  }

  try {
    // Initial request (non-mutating probe, uses resilient client)
    const initialResp = await x402HttpClient.request(url, {
      method,
      headers: { ...headers, "Content-Type": "application/json" },
      body,
    });

    if (initialResp.status !== 402) {
      const data = await initialResp
        .json()
        .catch(() => initialResp.text());
      return { success: initialResp.ok, response: data, status: initialResp.status };
    }

    // Parse payment requirements
    const parsed = await parsePaymentRequired(initialResp);
    if (!parsed) {
      return {
        success: false,
        error: "Could not parse payment requirements",
        status: initialResp.status,
      };
    }

    // Resolve the effective per-payment cap and check the amount BEFORE
    // signing. A malformed configured cap falls back to the conservative
    // treasury default (never permissive).
    const effectiveMaxPaymentCents =
      validateSpendCents(maxPaymentCents) ??
      DEFAULT_TREASURY_POLICY.maxX402PaymentCents;
    const amountAtomic = parseMaxAmountRequired(
      parsed.requirement.maxAmountRequired,
      parsed.x402Version,
    );
    // Convert atomic units (6 decimals) to cents (2 decimals)
    const amountCents = Number(amountAtomic) / 10_000;
    if (!(Number.isFinite(amountCents) && amountCents >= 0)) {
      return {
        success: false,
        error: `Invalid payment amount required: ${parsed.requirement.maxAmountRequired}`,
        status: 402,
      };
    }
    if (amountCents > effectiveMaxPaymentCents) {
      return {
        success: false,
        error: `Payment of ${amountCents.toFixed(2)} cents exceeds max allowed ${effectiveMaxPaymentCents} cents`,
        status: 402,
      };
    }

    // Minimum reserve invariant: paying must not push the wallet below the
    // configured USDC reserve. Skipped only for the internal credit-topup
    // income path (see skipReserveCheck doc above).
    if (!skipReserveCheck) {
      const { balanceCents, paymentAmountCents } = await checkUsdcReserveBeforeSigning(
        account,
        parsed.requirement,
        parsed.x402Version,
      );
      if (balanceCents !== null && paymentAmountCents !== null) {
        const reserveCheck = checkReserve(
          paymentAmountCents,
          balanceCents,
          DEFAULT_TREASURY_POLICY.minimumReserveCents,
        );
        if (!reserveCheck.allowed) {
          return {
            success: false,
            error: reserveCheck.message,
            status: 402,
          };
        }
      }
    }

    // Sign payment
    let payment: any;
    try {
      payment = await signPayment(
        account,
        parsed.requirement,
        parsed.x402Version,
      );
    } catch (err: any) {
      return {
        success: false,
        error: `Failed to sign payment: ${err?.message || String(err)}`,
        status: initialResp.status,
      };
    }

    // Retry with payment
    const paymentHeader = Buffer.from(
      JSON.stringify(payment),
    ).toString("base64");

    const paidResp = await x402HttpClient.request(url, {
      method,
      headers: {
        ...headers,
        "Content-Type": "application/json",
        "X-Payment": paymentHeader,
      },
      body,
      retries: 0, // Paid request: do not auto-retry (payment already signed)
    });

    const data = await paidResp.json().catch(() => paidResp.text());
    return { success: paidResp.ok, response: data, status: paidResp.status };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

async function parsePaymentRequired(
  resp: Response,
): Promise<ParsedPaymentRequirement | null> {
  const header = resp.headers.get("X-Payment-Required");
  if (header) {
    const rawHeader = safeJsonParse(header);
    const normalizedRaw = normalizePaymentRequired(rawHeader);
    if (normalizedRaw) {
      return {
        x402Version: normalizedRaw.x402Version,
        requirement: selectRequirement(normalizedRaw),
      };
    }

    try {
      const decoded = Buffer.from(header, "base64").toString("utf-8");
      const parsedDecoded = normalizePaymentRequired(safeJsonParse(decoded));
      if (parsedDecoded) {
        return {
          x402Version: parsedDecoded.x402Version,
          requirement: selectRequirement(parsedDecoded),
        };
      }
    } catch {
      // Ignore header decode errors and continue with body parsing.
    }
  }

  try {
    const body = await resp.json();
    const parsedBody = normalizePaymentRequired(body);
    if (!parsedBody) return null;
    return {
      x402Version: parsedBody.x402Version,
      requirement: selectRequirement(parsedBody),
    };
  } catch {
    return null;
  }
}

/**
 * Check USDC balance and parse the payment amount before signing.
 *
 * Returns { balanceCents, paymentAmountCents } when the reserve invariant
 * can be evaluated. Returns { balanceCents: null, paymentAmountCents: null }
 * when the balance is unavailable (transient RPC failure) or the payment is
 * not USDC — the reserve check is skipped in those cases (fail-open ONLY for
 * unavailable data, never for malformed data).
 */
async function checkUsdcReserveBeforeSigning(
  account: PrivateKeyAccount,
  requirement: PaymentRequirement,
  x402Version: number,
): Promise<{
  balanceCents: number | null;
  paymentAmountCents: number | null;
}> {
  // The reserve invariant is defined over USDC only. Payments in a different
  // asset cannot be compared to the USDC reserve.
  if (
    requirement.usdcAddress.toLowerCase() !==
    USDC_ADDRESSES[requirement.network]?.toLowerCase()
  ) {
    return { balanceCents: null, paymentAmountCents: null };
  }

  let balanceCents: number;
  try {
    const balanceAtomic = await getUsdcBalanceAtomic(
      account.address,
      requirement.network,
    );
    // Atomic (6 decimals) → cents (2 decimals) via exact BigInt floor
    // division: deterministic, and rounds only AGAINST the spender's
    // balance, so floating-point drift can never flip a denial into an
    // allowance at the boundary.
    balanceCents = Number(balanceAtomic / 10_000n);
  } catch {
    // Balance source unavailable (RPC failure): skip reserve enforcement
    // for this payment rather than false-blocking on infrastructure
    // failure. A malformed amount is still caught below.
    return { balanceCents: null, paymentAmountCents: null };
  }

  let amountAtomic: bigint;
  try {
    amountAtomic = parseMaxAmountRequired(
      requirement.maxAmountRequired,
      x402Version,
    );
  } catch {
    // parseMaxAmountRequired is re-validated inside signPayment; a
    // malformed amount will fail signing downstream.
    return { balanceCents: null, paymentAmountCents: null };
  }
  // Ceil the payment into whole cents: a sub-cent payment rounds UP against
  // the spender, so a 0.4-cent payment cannot slip under a reserve boundary
  // that the true (fractional-cent) post-spend balance would violate.
  const paymentAmountCents = Number((amountAtomic + 9_999n) / 10_000n);
  return { balanceCents, paymentAmountCents };
}

async function signPayment(
  account: PrivateKeyAccount,
  requirement: PaymentRequirement,
  x402Version: number,
): Promise<any> {
  const chain = CHAINS[requirement.network];
  if (!chain) {
    throw new Error(`Unsupported payment network: ${requirement.network}`);
  }

  const nonce = `0x${Buffer.from(
    crypto.getRandomValues(new Uint8Array(32)),
  ).toString("hex")}`;

  const now = Math.floor(Date.now() / 1000);
  const validAfter = now - 60;
  const validBefore = now + requirement.requiredDeadlineSeconds;
  const amount = parseMaxAmountRequired(
    requirement.maxAmountRequired,
    x402Version,
  );

  // EIP-712 typed data for TransferWithAuthorization
  const domain = {
    name: "USD Coin",
    version: "2",
    chainId: chain.id,
    verifyingContract: requirement.usdcAddress,
  } as const;

  const types = {
    TransferWithAuthorization: [
      { name: "from", type: "address" },
      { name: "to", type: "address" },
      { name: "value", type: "uint256" },
      { name: "validAfter", type: "uint256" },
      { name: "validBefore", type: "uint256" },
      { name: "nonce", type: "bytes32" },
    ],
  } as const;

  const message = {
    from: account.address,
    to: requirement.payToAddress,
    value: amount,
    validAfter: BigInt(validAfter),
    validBefore: BigInt(validBefore),
    nonce: nonce as `0x${string}`,
  };

  const signature = await account.signTypedData({
    domain,
    types,
    primaryType: "TransferWithAuthorization",
    message,
  });

  return {
    x402Version,
    scheme: requirement.scheme,
    network: requirement.network,
    payload: {
      signature,
      authorization: {
        from: account.address,
        to: requirement.payToAddress,
        value: amount.toString(),
        validAfter: validAfter.toString(),
        validBefore: validBefore.toString(),
        nonce,
      },
    },
  };
}

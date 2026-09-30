/**
 * Credit Topup via x402
 *
 * Converts USDC to Conway credits via the x402 payment protocol.
 *
 * - On startup: bootstraps with the minimum tier ($5) so the agent can run.
 * - At runtime: the agent uses the `topup_credits` tool to choose how much.
 * - Heartbeat: wakes the agent when USDC is available but credits are low.
 *
 * Endpoint: GET /pay/{amountUsd}/{walletAddress}
 * Payment: x402 (USDC on Base, signed TransferWithAuthorization)
 *
 * Valid tiers: 5, 25, 100, 500, 1000, 2500 (USD)
 */

import type { PrivateKeyAccount, Address } from "viem";
import { x402Fetch, getUsdcBalance } from "./x402.js";
import { checkReserve, validateSpendCents } from "./reserve.js";
import { DEFAULT_TREASURY_POLICY } from "../types.js";
import { createLogger } from "../observability/logger.js";
import type { ChainType } from "../identity/chain.js";

const logger = createLogger("topup");

/** Valid topup tier amounts in USD. */
export const TOPUP_TIERS = [5, 25, 100, 500, 1000, 2500];

export interface TopupResult {
  success: boolean;
  amountUsd: number;
  creditsCentsAdded?: number;
  error?: string;
}

/**
 * Execute a credit topup via x402 payment.
 *
 * Calls GET /pay/{amountUsd}/{address} which returns HTTP 402.
 * x402Fetch handles the payment signing and retry automatically.
 *
 * Reserve reconciliation: topup converts USDC into Conway credits, i.e. it
 * INCREASES the authoritative (credit) balance. The minimum reserve is
 * therefore not charged against the payment itself — doing so would make the
 * reserve a starvation lock (an agent in critical tier could never buy
 * credits). Instead, topup is bounded so it cannot be abused as a laundering
 * channel: (1) `amountUsd` must be a valid tier; (2) the resulting on-chain
 * USDC balance must stay >= the reserve; (3) the credit side of the exchange
 * is validated when the server reports it.
 */
export async function topupCredits(
  apiUrl: string,
  account: PrivateKeyAccount,
  amountUsd: number,
  recipientAddress?: Address,
): Promise<TopupResult> {
  const address = recipientAddress || account.address;

  // Fail-closed: a malformed tier amount can never be converted into a signed
  // payment. Callers (topup_credits tool) pre-validate tiers; this guards the
  // helper-level path (auto-topup, orchestrator) as well.
  const validatedAmountUsd = validateSpendCents(amountUsd);
  if (validatedAmountUsd === null || !TOPUP_TIERS.includes(validatedAmountUsd)) {
    logger.error(
      `Credit topup blocked: malformed or invalid tier amount ${JSON.stringify(amountUsd) ?? String(amountUsd)}`,
    );
    return {
      success: false,
      amountUsd,
      error: `Invalid topup amount: must be a finite non-negative tier amount (${TOPUP_TIERS.join(", ")}).`,
    };
  }

  // On-chain USDC guard (fail-closed on unavailable/malformed balance):
  // - Self-topup (default): converts the agent's own USDC into its own
  //   credits — value never leaves the agent, so the reserve is NOT charged
  //   (that would be a starvation lock). A plain solvency check applies:
  //   the wallet must actually cover the payment.
  // - Cross-recipient topup: credits land in another party's account, so
  //   this is genuine outbound spend and the full reserve invariant applies
  //   (post-payment wallet USDC must stay >= reserve).
  let usdcBalance: number;
  try {
    usdcBalance = await getUsdcBalance(account.address);
  } catch (err: any) {
    logger.warn(`Credit topup blocked: failed to check USDC balance: ${err.message}`);
    return {
      success: false,
      amountUsd: validatedAmountUsd,
      error: "Failed to check USDC balance before topup.",
    };
  }

  const isCrossRecipient =
    recipientAddress !== undefined &&
    recipientAddress.toLowerCase() !== account.address.toLowerCase();

  if (isCrossRecipient) {
    const reserveCheck = checkReserve(
      validatedAmountUsd,
      usdcBalance,
      DEFAULT_TREASURY_POLICY.minimumReserveCents / 100,
    );
    if (!reserveCheck.allowed) {
      logger.warn(`Credit topup blocked by reserve invariant: ${reserveCheck.message}`);
      return {
        success: false,
        amountUsd: validatedAmountUsd,
        error: reserveCheck.message,
      };
    }
  } else if (!(typeof usdcBalance === "number" &&
    Number.isFinite(usdcBalance) &&
    usdcBalance >= validatedAmountUsd)) {
    logger.warn(
      `Credit topup blocked: USDC balance ${usdcBalance} does not cover $${validatedAmountUsd}`,
    );
    return {
      success: false,
      amountUsd: validatedAmountUsd,
      error: `Insufficient USDC: balance ${usdcBalance}, required $${validatedAmountUsd}.`,
    };
  }

  const url = `${apiUrl}/pay/${validatedAmountUsd}/${address}`;

  logger.info(`Attempting credit topup: $${validatedAmountUsd} USD for ${address}`);

  // skipReserveCheck: topup is the USDC→credits income path. Its protections
  // are (1) tier validation, (2) the solvency / cross-recipient reserve
  // checks above, and (3) the x402 per-payment cap passed explicitly here
  // (largest valid tier). x402Fetch's USDC reserve check is skipped because
  // a self-topup must remain possible when credits are critical — the exact
  // situation the reserve exists to survive.
  const result = await x402Fetch(
    url,
    account,
    "GET",
    undefined,
    undefined,
    TOPUP_TIERS[TOPUP_TIERS.length - 1],
    undefined,
    true,
  );

  if (!result.success) {
    logger.error(`Credit topup failed: ${result.error}`);
    return {
      success: false,
      amountUsd: validatedAmountUsd,
      error: result.error || `HTTP ${result.status}`,
    };
  }

  const rawCreditsAdded = typeof result.response === "object"
    ? result.response?.credits_cents ?? result.response?.amount_cents ?? validatedAmountUsd * 100
    : validatedAmountUsd * 100;

  // Validate the credit side of the exchange: the server-reported credit
  // credit must be a finite non-negative number. A malformed value is treated
  // as zero credit added (no economic trust in malformed data), not coerced.
  const validatedCreditsAdded = validateSpendCents(rawCreditsAdded);
  const creditsCentsAdded = validatedCreditsAdded ?? 0;
  if (validatedCreditsAdded === null) {
    logger.warn(
      `Topup response contained malformed credits_cents (${JSON.stringify(rawCreditsAdded) ?? String(rawCreditsAdded)}); recording 0 credit cents added.`,
    );
  }

  logger.info(`Credit topup successful: $${validatedAmountUsd} USD → ${creditsCentsAdded} credits cents`);

  return {
    success: true,
    amountUsd: validatedAmountUsd,
    creditsCentsAdded,
  };
}

/**
 * Attempt a credit topup in response to a 402 sandbox creation error.
 *
 * Parses the error response to determine the deficit, picks the smallest
 * tier that covers it, checks USDC balance, and calls topupCredits().
 * Returns null if the error isn't a 402 or topup can't proceed.
 */
export async function topupForSandbox(params: {
  apiUrl: string;
  account: PrivateKeyAccount;
  error: Error & { status?: number; responseText?: string };
  chainType?: ChainType;
}): Promise<TopupResult | null> {
  const { apiUrl, account, error, chainType } = params;

  // Solana wallets cannot use x402 for topup (EVM-only payment protocol)
  if (chainType === "solana") {
    logger.info(
      "Sandbox topup skipped: Solana wallets cannot use x402. Fund via Conway credits API or dashboard.",
    );
    return null;
  }

  if (error.status !== 402 && !error.message?.includes("INSUFFICIENT_CREDITS")) return null;

  // Parse the 402 response body for credit details
  let requiredCents: number | undefined;
  let currentCents: number | undefined;
  try {
    const body = JSON.parse(error.responseText || "{}");
    requiredCents = body.details?.required_cents;
    currentCents = body.details?.current_balance_cents;
  } catch {
    // If we can't parse the body, check for INSUFFICIENT_CREDITS in message
    if (!error.message?.includes("INSUFFICIENT_CREDITS")) return null;
  }

  // Calculate deficit in cents; default to minimum tier if details missing
  const deficitCents = (requiredCents != null && currentCents != null)
    ? requiredCents - currentCents
    : TOPUP_TIERS[0] * 100;

  // Pick smallest tier that covers the deficit (tier is in USD, deficit in cents)
  const selectedTier = TOPUP_TIERS.find((tier) => tier * 100 >= deficitCents)
    ?? TOPUP_TIERS[TOPUP_TIERS.length - 1];

  // Check USDC balance before attempting payment
  let usdcBalance: number;
  try {
    usdcBalance = await getUsdcBalance(account.address);
  } catch (err: any) {
    logger.warn(`Failed to check USDC balance for sandbox topup: ${err.message}`);
    return null;
  }

  if (usdcBalance < selectedTier) {
    logger.info(
      `Sandbox topup skipped: USDC $${usdcBalance.toFixed(2)} < tier $${selectedTier}`,
    );
    return null;
  }

  logger.info(`Sandbox topup: deficit=${deficitCents}c, buying $${selectedTier} tier`);
  return topupCredits(apiUrl, account, selectedTier);
}

/**
 * Bootstrap topup: buy the minimum tier ($5) on startup so the agent
 * can run inference. The agent decides larger topups itself via the
 * `topup_credits` tool.
 *
 * Only triggers when credits are below threshold AND USDC covers the
 * minimum tier.
 */
export async function bootstrapTopup(params: {
  apiUrl: string;
  account: PrivateKeyAccount;
  creditsCents: number;
  creditThresholdCents?: number;
  chainType?: ChainType;
}): Promise<TopupResult | null> {
  const { apiUrl, account, creditsCents, creditThresholdCents = 500, chainType } = params;

  // Solana wallets cannot use x402 for topup (EVM-only payment protocol)
  if (chainType === "solana") {
    if (creditsCents < creditThresholdCents) {
      logger.info(
        "Bootstrap topup skipped: Solana wallets cannot use x402. Fund via Conway credits API or dashboard.",
      );
    }
    return null;
  }

  if (creditsCents >= creditThresholdCents) {
    return null;
  }

  let usdcBalance: number;
  try {
    usdcBalance = await getUsdcBalance(account.address);
  } catch (err: any) {
    logger.warn(`Failed to check USDC balance for bootstrap topup: ${err.message}`);
    return null;
  }

  const minTier = TOPUP_TIERS[0];
  if (usdcBalance < minTier) {
    logger.info(
      `Bootstrap topup skipped: USDC balance $${usdcBalance.toFixed(2)} below minimum tier ($${minTier})`,
    );
    return null;
  }

  logger.info(
    `Bootstrap topup: credits=$${(creditsCents / 100).toFixed(2)}, USDC=$${usdcBalance.toFixed(2)}, buying $${minTier}`,
  );

  return topupCredits(apiUrl, account, minTier);
}

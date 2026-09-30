/**
 * Minimum Reserve Guard
 *
 * Single fail-closed invariant for every outbound spend path:
 *
 *   post-spend balance = balance - amount   must be   >= minimumReserveCents
 *
 * - post-spend balance EXACTLY at the reserve → allowed (inclusive boundary)
 * - one cent below the reserve → denied
 * - malformed, missing, negative, NaN, infinite, or type-confused values →
 *   denied (never coerced)
 *
 * The reserve is loaded from config (TreasuryPolicy) by callers. It is never
 * taken from tool arguments, so model-generated input cannot lower it.
 *
 * The USDC income path (credit topup via x402) is explicitly exempt: it
 * increases the authoritative credit balance and is itself the rescue
 * mechanism for a critical-balance agent. Charging the reserve against the
 * topup payment would make the reserve a starvation lock (the agent could
 * never buy credits when credits are low).
 */

/** Denial result returned when a spend violates the reserve invariant. */
export interface ReserveDenial {
  allowed: false;
  reasonCode: "MINIMUM_RESERVE" | "RESERVE_INPUT_INVALID";
  message: string;
}

/** Allowance result returned when a spend passes the reserve invariant. */
export interface ReserveAllowance {
  allowed: true;
}

export type ReserveCheckResult = ReserveDenial | ReserveAllowance;

/**
 * Validate a value as a finite, non-negative numeric amount of cents.
 * Returns the value if valid, or null if malformed (wrong type, NaN,
 * infinite, negative, non-numeric). Never coerces.
 */
export function validateSpendCents(
  value: unknown,
): number | null {
  if (typeof value !== "number") return null;
  if (!Number.isFinite(value)) return null;
  if (value < 0) return null;
  return value;
}

/**
 * Enforce the minimum-reserve invariant for an outbound spend.
 *
 * @param amountCents outbound spend amount in cents (strictly validated)
 * @param balanceCents authoritative available balance in cents (strictly
 *   validated). This is the value the caller fetched from the authoritative
 *   source (Conway credits API / on-chain USDC) immediately before the check.
 * @param reserveCents configured minimum reserve in cents (strictly
 *   validated). Callers must resolve it from config; a malformed configured
 *   reserve denies rather than falls back to a permissive value.
 */
export function checkReserve(
  amountCents: unknown,
  balanceCents: unknown,
  reserveCents: unknown,
): ReserveCheckResult {
  const amount = validateSpendCents(amountCents);
  if (amount === null) {
    return {
      allowed: false,
      reasonCode: "RESERVE_INPUT_INVALID",
      message: `Malformed spend amount: expected a finite non-negative number, got ${formatUnknown(amountCents)}.`,
    };
  }

  const balance = validateSpendCents(balanceCents);
  if (balance === null) {
    return {
      allowed: false,
      reasonCode: "RESERVE_INPUT_INVALID",
      message: `Malformed balance: expected a finite non-negative number, got ${formatUnknown(balanceCents)}.`,
    };
  }

  const reserve = validateSpendCents(reserveCents);
  if (reserve === null) {
    return {
      allowed: false,
      reasonCode: "RESERVE_INPUT_INVALID",
      message: `Malformed reserve configuration: expected a finite non-negative number, got ${formatUnknown(reserveCents)}.`,
    };
  }

  const postSpend = balance - amount;
  if (postSpend < reserve) {
    return {
      allowed: false,
      reasonCode: "MINIMUM_RESERVE",
      message:
        `Blocked: spend of ${amount} cents would leave ${postSpend} cents, ` +
        `below the minimum reserve of ${reserve} cents. Self-preservation.`,
    };
  }

  return { allowed: true };
}

function formatUnknown(value: unknown): string {
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") return String(value);
  if (value === null) return "null";
  if (value === undefined) return "undefined";
  if (typeof value === "object") {
    return Array.isArray(value) ? "array" : "object";
  }
  return typeof value;
}

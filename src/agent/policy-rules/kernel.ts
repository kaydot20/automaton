/**
 * Kernel Integrity Policy Rule (M1-B6, preflight §10)
 *
 * While the protected-kernel boot check is degraded (manifest mismatch,
 * missing kernel file, or unusable manifest), this rule DENIES every
 * financial, spawn, and self-modification tool call. The decision is made by
 * deterministic code outside model reasoning: no prompt, tool argument, or
 * input source can re-enable these capabilities while the kernel is
 * unverified — only a process restart with a verified kernel can.
 */

import type { PolicyRule, PolicyRequest, PolicyRuleResult } from "../../types.js";
import { isKernelDegraded } from "../../governance/kernel.js";

export const KERNEL_DEGRADED_REASON_CODE = "KERNEL_INTEGRITY_DEGRADED";

/** Financial authority tools — denied while the kernel is unverified. */
const FINANCIAL_TOOLS = [
  "transfer_credits",
  "fund_child",
  "topup_credits",
  "x402_fetch",
] as const;

/** Spawn / replication tools — denied while the kernel is unverified. */
const SPAWN_TOOLS = [
  "spawn_child",
  "delete_sandbox",
] as const;

/** Self-modification tools — denied while the kernel is unverified. */
const SELF_MOD_TOOLS = [
  "edit_own_file",
  "write_file",
  "install_mcp_server",
  "install_npm_package",
  "pull_upstream",
  "reset_to_upstream",
  "revert_last_edit",
] as const;

export const KERNEL_DEGRADED_TOOLS: readonly string[] = Object.freeze([
  ...FINANCIAL_TOOLS,
  ...SPAWN_TOOLS,
  ...SELF_MOD_TOOLS,
]);

function deny(reason: string): PolicyRuleResult {
  return {
    rule: "kernel.integrity_gate",
    action: "deny",
    reasonCode: KERNEL_DEGRADED_REASON_CODE,
    humanMessage: `Protected kernel integrity check failed — financial, spawn, and self-modification tools are disabled until the kernel is verified. ${reason}`,
  };
}

/**
 * Deny financial/spawn/self-mod tools when the boot-time kernel integrity
 * check left the process in degraded mode. First deny wins in the policy
 * engine, so this rule only needs to return the deny verdict.
 */
export function createKernelIntegrityRule(): PolicyRule {
  return {
    id: "kernel.integrity_gate",
    description: "Deny financial/spawn/self-mod tools while protected-kernel integrity is unverified (M1-B6)",
    priority: 50, // unique minimum: nothing may outrank kernel integrity
    appliesTo: { by: "name", names: [...KERNEL_DEGRADED_TOOLS] },
    evaluate(_request: PolicyRequest): PolicyRuleResult | null {
      if (!isKernelDegraded()) {
        return null;
      }
      return deny(
        "Boot-time manifest verification reported a mismatch, a missing kernel file, or an unusable manifest.",
      );
    },
  };
}

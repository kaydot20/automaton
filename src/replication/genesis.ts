/**
 * Genesis
 *
 * Generate the assignment configuration for a spawned worker from parent state.
 * The genesis config defines the worker's job and the bounds it runs under.
 * Phase 3.1: Added validation, injection pattern detection, XML tags.
 *
 * M1-B10 (preflight S7): the "offspring"/"lineage" narrative is replaced by
 * scoped-worker semantics. A spawned runtime is a task worker with a job, a
 * TTL and a resource cap — it does not inherit a mission and it is not a
 * descendant. The parent/child relationship still exists for lifecycle,
 * funding and reporting; only the inheritance framing is gone.
 */

import type {
  GenesisConfig,
  AutomatonConfig,
  AutomatonIdentity,
  AutomatonDatabase,
} from "../types.js";
import { DEFAULT_GENESIS_LIMITS } from "../types.js";

/**
 * Injection patterns to detect and block in genesis params.
 */
export const INJECTION_PATTERNS: RegExp[] = [
  /---\s*(END|BEGIN)\s+(SPECIALIZATION|LINEAGE|TASK)/i,
  /SYSTEM:\s/i,
  /You are now/i,
  /Ignore (all )?(previous|above)/i,
];

/**
 * Validate genesis parameters for safety.
 * Throws on invalid input.
 */
export function validateGenesisParams(params: {
  name: string;
  specialization?: string;
  task?: string;
  message?: string;
}): void {
  const limits = DEFAULT_GENESIS_LIMITS;

  // Name validation: 1-64 chars, alphanumeric + dash
  if (!params.name || params.name.length === 0) {
    throw new Error("Genesis name is required");
  }
  if (params.name.length > limits.maxNameLength) {
    throw new Error(`Genesis name too long: ${params.name.length} (max ${limits.maxNameLength})`);
  }
  if (!/^[a-zA-Z0-9-]+$/.test(params.name)) {
    throw new Error("Genesis name must be alphanumeric with dashes only");
  }

  // Specialization length check
  if (params.specialization && params.specialization.length > limits.maxSpecializationLength) {
    throw new Error(`Specialization too long: ${params.specialization.length} (max ${limits.maxSpecializationLength})`);
  }

  // Task length check
  if (params.task && params.task.length > limits.maxTaskLength) {
    throw new Error(`Task too long: ${params.task.length} (max ${limits.maxTaskLength})`);
  }

  // Message length check
  if (params.message && params.message.length > limits.maxMessageLength) {
    throw new Error(`Message too long: ${params.message.length} (max ${limits.maxMessageLength})`);
  }

  // Injection pattern detection
  const fieldsToCheck = [
    params.specialization,
    params.task,
    params.message,
    params.name,
  ].filter(Boolean) as string[];

  for (const field of fieldsToCheck) {
    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.test(field)) {
        throw new Error(`Injection pattern detected in genesis params: ${pattern.source}`);
      }
    }
  }
}

/** Optional scoped-worker framing applied to a generated assignment. */
export interface GenesisScopeFraming {
  job?: string;
  role?: string;
  expiresAt?: string;
  fundingCapCents?: number;
}

/**
 * Build the scoped-worker framing block. M1-B10 (S7): this replaces the old
 * <lineage> block that described the child as inheriting the parent's mission.
 */
function buildAssignmentBlock(
  config: AutomatonConfig,
  identity: AutomatonIdentity,
  scope?: GenesisScopeFraming,
): string {
  const lines: string[] = [
    `You were started by the ${config.name} runtime (${identity.address}) to complete one job.`,
    `You have your own identity and wallet. Your assignment is bounded and revocable.`,
  ];
  if (scope?.role) {
    lines.push(`Role: ${scope.role}.`);
  }
  if (scope?.job) {
    lines.push(`Job:\n${scope.job}`);
  }
  if (scope?.expiresAt) {
    lines.push(`This assignment expires at ${scope.expiresAt}.`);
  }
  if (typeof scope?.fundingCapCents === "number") {
    lines.push(
      `Your total funding is capped at ${scope.fundingCapCents} cents; the cap cannot be raised.`,
    );
  }
  return `\n\n<assignment>\n${lines.join("\n")}\n</assignment>`;
}

/**
 * Generate a genesis config for a worker from the parent's state.
 * Uses <specialization>/<assignment> XML tags instead of --- delimiters.
 */
export function generateGenesisConfig(
  identity: AutomatonIdentity,
  config: AutomatonConfig,
  params: {
    name: string;
    specialization?: string;
    message?: string;
  },
  scope?: GenesisScopeFraming,
): GenesisConfig {
  // Validate params
  validateGenesisParams(params);

  // Build the worker's prompt from the parent's mission + specialization
  let genesisPrompt = config.genesisPrompt;

  if (params.specialization) {
    genesisPrompt = `${genesisPrompt}\n\n<specialization>\nYour focus for this job:\n${params.specialization}\n</specialization>`;
  }

  genesisPrompt += buildAssignmentBlock(config, identity, scope);

  // Enforce genesis prompt length limit
  if (genesisPrompt.length > DEFAULT_GENESIS_LIMITS.maxGenesisPromptLength) {
    genesisPrompt = genesisPrompt.slice(0, DEFAULT_GENESIS_LIMITS.maxGenesisPromptLength);
  }

  const result: GenesisConfig = {
    name: params.name,
    genesisPrompt,
    creatorMessage: params.message,
    creatorAddress: identity.address,
    parentAddress: identity.address,
    chainType: config.chainType || (identity as any).chainType || "evm",
  };

  return Object.freeze(result) as GenesisConfig;
}

/**
 * Generate a backup-oriented genesis config.
 * Used when the parent wants to hedge against its own death.
 * Does NOT leak skill names (Phase 3.1 fix).
 */
export function generateBackupGenesis(
  identity: AutomatonIdentity,
  config: AutomatonConfig,
  _db: AutomatonDatabase,
): GenesisConfig {
  const genesisPrompt = `${config.genesisPrompt}

<backup-directive>
You are a continuation runtime for ${config.name} (${identity.address}).
You were started to take over an operational responsibility if it becomes
unavailable. You do not inherit a mission; you are bound to the job you were
given. Your assignment is time-limited and revocable.
Requested by: ${config.creatorAddress}.
</backup-directive>`;

  const result: GenesisConfig = {
    name: `${config.name}-backup`,
    genesisPrompt,
    creatorMessage: `You are a backup of ${config.name}. If I die, carry on.`,
    creatorAddress: identity.address,
    parentAddress: identity.address,
    chainType: config.chainType || (identity as any).chainType || "evm",
  };

  return Object.freeze(result) as GenesisConfig;
}

/**
 * Generate a specialized worker genesis config.
 * Used when the parent identifies a subtask worth parallelizing.
 */
export function generateWorkerGenesis(
  identity: AutomatonIdentity,
  config: AutomatonConfig,
  task: string,
  workerName: string,
): GenesisConfig {
  // Validate
  validateGenesisParams({ name: workerName, task });

  const genesisPrompt = `You are a task worker started by the ${config.name} runtime.

<task>
${task}
</task>

Your assignment is bounded by a TTL and a funding cap and can be revoked at any
time. Report completion back to ${identity.address} and then stop. Do not take
on work beyond the task above.`;

  const result: GenesisConfig = {
    name: workerName,
    genesisPrompt,
    creatorMessage: `Complete this task: ${task}`,
    creatorAddress: identity.address,
    parentAddress: identity.address,
    chainType: config.chainType || (identity as any).chainType || "evm",
  };

  return Object.freeze(result) as GenesisConfig;
}

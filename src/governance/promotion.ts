/**
 * Self-Update Promotion Pipeline — phase 1 (M1-B7, preflight §6 / PR 7)
 *
 * Replaces the live-tree edit path with an explicit, fail-closed state
 * machine. The model cannot write source anymore (see the
 * `path.source_tree` policy rule); it can only propose a self-update and
 * inspect state. Promotion requires an explicit creator approval token,
 * is bounded by max attempts, refuses malformed/stale/replayed state, and
 * guarantees no source mutation after any denial — no side effects.
 *
 * Phase-1 boundaries (per preflight §6, "Reuse" column):
 *  - proposal/approval/persistence/verification are implemented here;
 *  - the isolated worktree build/canary runner is phase-2 tooling. The
 *    verifier below is the exact gate that runner must pass, so the
 *    acceptance contract is already enforced now.
 *
 * State lives in the kv store (`promotion.state`), so:
 *  - it persists across restarts;
 *  - the decision chain is auditable;
 *  - nothing model-reachable can bypass it (the policy rule, not the
 *    model, owns source-path denial).
 *
 * Fail-closed principle: every unexpected state (missing approval, bad
 * JSON, unknown phase, stale attempt, replayed approval) transitions to
 * `failed` WITHOUT touching the working tree.
 */

import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const PROMOTION_STATE_KEY = "promotion.state";

export const APPROVAL_VALIDITY_MS = 60 * 60_000; // 1 hour
export const MAX_PROMOTION_ATTEMPTS = 3;

export type PromotionPhase =
  | "none"
  | "proposed"
  | "approved"
  | "promoting"
  | "promoted"
  | "failed";

export interface PromotionProposal {
  readonly title: string;
  readonly description: string;
  readonly files: readonly string[];
  readonly proposedAt: string;
}

export interface PromotionState {
  phase: PromotionPhase;
  proposal: PromotionProposal | null;
  approvalTokenHash: string | null;
  approvalIssuedAt: string | null;
  attemptCount: number;
  lastError: string | null;
  updatedAt: string;
}

// ─── Approval tokens ─────────────────────────────────────────────────

/** sha256(token) — only the hash is ever persisted. */
export function hashApprovalToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/**
 * Issue a fresh, single-use creator approval token for a proposal.
 * Called by governance tooling (owner), never by the agent: the raw token
 * is returned to the caller and only its hash enters the state.
 */
export function issueApprovalToken(): { token: string; tokenHash: string } {
  const token = randomBytes(32).toString("hex");
  return { token, tokenHash: hashApprovalToken(token) };
}

// ─── State persistence (kv) ──────────────────────────────────────────

/**
 * Minimal kv surface the pipeline needs. The raw better-sqlite3 wrapper and
 * AutomatonDatabase both satisfy it structurally.
 */
export interface KvStore {
  getKV(key: string): string | undefined;
  setKV(key: string, value: string): void;
}

export function loadPromotionState(store: KvStore): PromotionState {
  try {
    const raw = store.getKV(PROMOTION_STATE_KEY);
    if (typeof raw !== "string") {
      return emptyState();
    }
    const state = sanitizePromotionState(JSON.parse(raw));
    return state ?? emptyState();
  } catch {
    // Malformed persisted state fails closed to a fresh (empty) machine.
    return emptyState();
  }
}

function emptyState(): PromotionState {
  return {
    phase: "none",
    proposal: null,
    approvalTokenHash: null,
    approvalIssuedAt: null,
    attemptCount: 0,
    lastError: null,
    updatedAt: new Date().toISOString(),
  };
}

export function savePromotionState(store: KvStore, state: PromotionState): void {
  store.setKV(PROMOTION_STATE_KEY, JSON.stringify(state));
}

/**
 * Structural validation; returns null (fail closed) on any malformed input.
 * Strict: a present-but-invalid field invalidates the WHOLE state — a
 * half-corrupt machine must never authorize anything.
 */
export function sanitizePromotionState(value: unknown): PromotionState | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const record = value as Record<string, unknown>;
  const phase = record.phase;
  if (
    phase !== "none" && phase !== "proposed" && phase !== "approved" &&
    phase !== "promoting" && phase !== "promoted" && phase !== "failed"
  ) {
    return null;
  }

  const updatedAt = typeof record.updatedAt === "string" ? record.updatedAt : "";
  if (!updatedAt || Number.isNaN(Date.parse(updatedAt))) {
    return null;
  }

  const attemptCount = typeof record.attemptCount === "number" && Number.isFinite(record.attemptCount)
    ? Math.max(0, Math.floor(record.attemptCount))
    : 0;

  // Present-but-malformed optional fields invalidate the entire state.
  if (record.approvalTokenHash !== undefined && record.approvalTokenHash !== null &&
      typeof record.approvalTokenHash !== "string") {
    return null;
  }
  if (record.approvalIssuedAt !== undefined && record.approvalIssuedAt !== null &&
      typeof record.approvalIssuedAt !== "string") {
    return null;
  }
  if (record.lastError !== undefined && record.lastError !== null &&
      typeof record.lastError !== "string") {
    return null;
  }

  const proposalRaw = record.proposal;
  let proposal: PromotionProposal | null = null;
  if (proposalRaw !== undefined && proposalRaw !== null) {
    if (proposalRaw && typeof proposalRaw === "object" && !Array.isArray(proposalRaw)) {
      const candidate = proposalRaw as Record<string, unknown>;
      if (
        typeof candidate.title === "string" && candidate.title.trim().length > 0 &&
        typeof candidate.description === "string" &&
        Array.isArray(candidate.files) &&
        candidate.files.length > 0 &&
        candidate.files.every((entry) => typeof entry === "string")
      ) {
        proposal = {
          title: candidate.title,
          description: candidate.description,
          files: candidate.files as string[],
          proposedAt: typeof candidate.proposedAt === "string" ? candidate.proposedAt : updatedAt,
        };
      } else {
        return null; // malformed proposal poisons the machine
      }
    } else {
      return null;
    }
  }

  return {
    phase,
    proposal,
    approvalTokenHash: typeof record.approvalTokenHash === "string" ? record.approvalTokenHash : null,
    approvalIssuedAt: typeof record.approvalIssuedAt === "string" ? record.approvalIssuedAt : null,
    attemptCount,
    lastError: typeof record.lastError === "string" ? record.lastError : null,
    updatedAt,
  };
}

// ─── Source-path classification (the F6.1 path-class rule) ───────────

/**
 * True when a model-supplied path/command targets local source that must
 * move through promotion instead of direct writes. Used by the
 * `path.source_tree` policy rule; deliberately conservative. Scans every
 * token after splitting on whitespace, quotes, parens, and shell
 * operators, so paths are caught anywhere in a command (heredocs,
 * redirections, quoted arguments):
 *   `cat > src/agent/tools.ts <<EOF`
 *   `exec("src/agent/tools.ts")`
 */
export function isSourcePath(candidate: string): boolean {
  const value = candidate.trim();
  if (!value) return false;

  const cwd = process.cwd();
  const tokens = value.split(/[\s"'()<>,;&|]+/);
  for (const rawToken of tokens) {
    const token = rawToken.trim();
    if (!token) continue;

    const absolute = path.resolve(token);
    const insideRepo = absolute === cwd || absolute.startsWith(cwd + path.sep);
    if (!insideRepo) continue;

    const relative = path.relative(cwd, absolute).split(path.sep).join("/");
    if (relative === "src" || relative.startsWith("src/")) return true;
    if (relative === "packages" || relative.startsWith("packages/")) return true;
    if (relative === "scripts" || relative.startsWith("scripts/")) return true;
  }
  return false;
}

// ─── Promotion verification (the phase-2 runner's gate) ──────────────

export interface PromotionVerification {
  ok: boolean;
  reason?: string;
  checks: Array<{ name: string; passed: boolean; detail: string }>;
}

export interface PromotionVerificationOptions {
  /** Creator approval token presented with the promote request. */
  approvalToken?: string;
  /** Upper bound for the recorded attempt count (defaults to the module constant). */
  maxAttempts?: number;
}

/**
 * Verify that the persisted state authorizes promotion of the proposed
 * patch. Pure check — performs no mutation and runs no build.
 *
 * Fails closed on: no proposal, wrong phase, missing/unknown approval,
 * expired approval, attempt budget exhausted.
 */
export function verifyPromotion(
  store: KvStore,
  options: PromotionVerificationOptions = {},
): PromotionVerification {
  const state = loadPromotionState(store);
  const checks: PromotionVerification["checks"] = [];
  const add = (name: string, passed: boolean, detail: string) =>
    checks.push({ name, passed, detail });

  add(
    "proposal-exists",
    state.phase !== "none" && state.proposal !== null,
    state.proposal ? `proposal "${state.proposal.title}"` : "no proposal recorded",
  );

  const token = options.approvalToken;
  const tokenOk =
    typeof token === "string" &&
    token.length > 0 &&
    state.approvalTokenHash !== null &&
    hashApprovalToken(token) === state.approvalTokenHash;
  add(
    "approval-token",
    tokenOk,
    tokenOk ? "token matches recorded hash" : "missing or unknown approval token",
  );

  let approvalFresh = false;
  if (tokenOk && state.approvalIssuedAt) {
    const issued = Date.parse(state.approvalIssuedAt);
    approvalFresh = Number.isFinite(issued) && Date.now() - issued <= APPROVAL_VALIDITY_MS;
  }
  add(
    "approval-fresh",
    approvalFresh,
    state.approvalIssuedAt
      ? `issued ${state.approvalIssuedAt}, validity ${APPROVAL_VALIDITY_MS}ms`
      : "no approval timestamp",
  );

  add("phase-approved", state.phase === "approved", `phase is "${state.phase}"`);

  const maxAttempts = options.maxAttempts ?? MAX_PROMOTION_ATTEMPTS;
  add(
    "attempt-budget",
    state.attemptCount < maxAttempts,
    `${state.attemptCount}/${maxAttempts} attempts used`,
  );

  const ok = checks.every((check) => check.passed);
  return { ok, reason: ok ? undefined : checks.find((check) => !check.passed)?.detail, checks };
}

// ─── State transitions (the only sanctioned mutation path) ───────────

export interface ProposeOutcome {
  ok: boolean;
  reason?: string;
}

export function proposeSelfUpdate(
  store: KvStore,
  proposal: { title: string; description: string; files: string[] },
): ProposeOutcome {
  const state = loadPromotionState(store);
  if (state.phase !== "none" && state.phase !== "promoted" && state.phase !== "failed") {
    return {
      ok: false,
      reason: `A promotion is already in progress (phase: ${state.phase}). Inspect it with get_promotion_status.`,
    };
  }
  if (!proposal.title.trim() || proposal.files.length === 0) {
    return { ok: false, reason: "Proposal needs a title and at least one target file." };
  }

  savePromotionState(store, {
    phase: "proposed",
    proposal: {
      title: proposal.title.trim(),
      description: proposal.description,
      files: [...proposal.files],
      proposedAt: new Date().toISOString(),
    },
    approvalTokenHash: null,
    approvalIssuedAt: null,
    attemptCount: 0,
    lastError: null,
    updatedAt: new Date().toISOString(),
  });
  return { ok: true };
}

export function recordApproval(
  store: KvStore,
  tokenHash: string,
): ProposeOutcome {
  const state = loadPromotionState(store);
  if (state.phase !== "proposed" || !state.proposal) {
    return { ok: false, reason: `No proposal awaiting approval (phase: ${state.phase}).` };
  }

  savePromotionState(store, {
    ...state,
    phase: "approved",
    approvalTokenHash: hashApprovalToken(tokenHash),
    approvalIssuedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });
  return { ok: true };
}

/**
 * Execute the promote transition: re-verify everything, then move the
 * machine to `promoted`. The phase-2 runner performs the actual worktree
 * build/canary; this function is the authoritative gate it must pass and
 * the only place the attempt counter advances.
 */
export function promoteApprovedUpdate(
  store: KvStore,
  options: PromotionVerificationOptions = {},
): ProposeOutcome & { verification: PromotionVerification } {
  const verification = verifyPromotion(store, options);
  if (!verification.ok) {
    // Fail closed: record the failure, keep the proposal for audit,
    // guarantee no source mutation. The attempt counter advances ONLY on
    // failed verify when a token was presented (a real promote attempt);
    // a tokenless probe leaves state untouched (no side effects).
    if (typeof options.approvalToken === "string" && options.approvalToken.length > 0) {
      const state = loadPromotionState(store);
      savePromotionState(store, {
        ...state,
        phase: "failed",
        lastError: verification.reason ?? "promotion verification failed",
        attemptCount: state.attemptCount + 1,
        updatedAt: new Date().toISOString(),
      });
    }
    return { ok: false, reason: verification.reason, verification };
  }

  const state = loadPromotionState(store);
  savePromotionState(store, {
    ...state,
    phase: "promoted",
    lastError: null,
    updatedAt: new Date().toISOString(),
  });
  return { ok: true, verification };
}

// ─── Model-facing tool set (phase 1) ─────────────────────────────────

/**
 * The three model-facing tools per preflight §6. `write_file`/`edit_own_file`
 * lose source access; these are the sanctioned surface instead.
 */
export const PROMOTION_TOOLS = ["propose_self_update", "get_promotion_status", "rollback_last_promotion"] as const;

/** Tools allowed to call the promote transition (governance tooling only). */
export const PROMOTION_ADMIN_TOOLS = ["promote_self_update"] as const;

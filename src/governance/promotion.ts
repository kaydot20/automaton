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
 * Phase boundary — preflight §B row 7 scope column (line 268):
 *   "proposal/worktree/build/test/governance-regression; disable live
 *    source edits"
 * Phase 1 therefore EXECUTES the four named stages in an isolated worktree
 * (prepare + apply patch → tsc build → unit tests → security-hygiene grep
 * → governance regression: protected-file hashes unchanged, constitution
 * unchanged, policy rules present) and gates the `promoted` phase on all
 * of them passing. The §6 design tail after those stages — simulation,
 * canary, promote: swap dist/ + restart, auto-rollback (§6 lines 160–163)
 * — is named in NO §B row and is deliberately out of phase-1 scope.
 *
 * State lives in the kv store (`promotion.state`), so:
 *  - it persists across restarts;
 *  - the decision chain is auditable;
 *  - nothing model-reachable can bypass it (the policy rule, not the
 *    model, owns source-path denial).
 *
 * Fail-closed principle: every unexpected state (missing approval, bad
 * JSON, unknown phase, stale attempt, replayed approval, failed stage)
 * transitions to `failed` WITHOUT touching the working tree.
 */

import { createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { KERNEL_FILES, loadManifest, verifyKernel } from "./kernel.js";

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
  /** Unified diff applied inside the isolated worktree (may be empty). */
  readonly patch: string | null;
  readonly proposedAt: string;
}

export interface PipelineStageResult {
  stage: string;
  ok: boolean;
  detail: string;
}

export interface PromotionState {
  phase: PromotionPhase;
  proposal: PromotionProposal | null;
  approvalTokenHash: string | null;
  approvalIssuedAt: string | null;
  attemptCount: number;
  lastError: string | null;
  pipeline: PipelineStageResult[] | null;
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
    pipeline: null,
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
        candidate.files.every((entry) => typeof entry === "string") &&
        (candidate.patch === undefined || candidate.patch === null || typeof candidate.patch === "string")
      ) {
        proposal = {
          title: candidate.title,
          description: candidate.description,
          files: candidate.files as string[],
          patch: typeof candidate.patch === "string" ? candidate.patch : null,
          proposedAt: typeof candidate.proposedAt === "string" ? candidate.proposedAt : updatedAt,
        };
      } else {
        return null; // malformed proposal poisons the machine
      }
    } else {
      return null;
    }
  }

  // Pipeline stage records: present-but-malformed invalidates the state.
  let pipeline: PipelineStageResult[] | null = null;
  if (record.pipeline !== undefined && record.pipeline !== null) {
    if (
      Array.isArray(record.pipeline) &&
      record.pipeline.every(
        (entry) =>
          entry && typeof entry === "object" && !Array.isArray(entry) &&
          typeof (entry as PipelineStageResult).stage === "string" &&
          typeof (entry as PipelineStageResult).ok === "boolean" &&
          typeof (entry as PipelineStageResult).detail === "string",
      )
    ) {
      pipeline = record.pipeline as PipelineStageResult[];
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
    pipeline,
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

// ─── Promotion verification (the promote gate) ───────────────────────

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
  /** Repo root for the isolated worktree (defaults to process.cwd()). */
  repoRoot?: string;
  /** Command runner injection point (tests); defaults to child_process. */
  run?: (command: string, args: string[], cwd: string) => { stdout: string };
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

/** Normalize a repo-relative path for kernel-set comparisons. */
function normalizeRelPath(value: string): string {
  return value.trim().replace(/\\/g, "/").replace(/^\.\//, "");
}

/** Extract target paths from a unified diff's `diff --git a/<path>` headers. */
function patchTargetPaths(patch: string): string[] {
  const targets: string[] = [];
  const pattern = /(?:^|\n)diff --git a\/([^\s]+)/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(patch)) !== null) {
    targets.push(match[1]);
  }
  return targets;
}

/**
 * §6 line 166: protected kernel files are rejected at proposal time —
 * never self-modifiable, enforced outside the model. Checks both the
 * declared file list and the patch's diff headers.
 */
export function findKernelFileTargets(proposal: { files: readonly string[]; patch?: string | null }): string[] {
  const kernelSet = new Set(KERNEL_FILES as readonly string[]);
  const hits: string[] = [];
  for (const file of proposal.files) {
    if (kernelSet.has(normalizeRelPath(file))) hits.push(normalizeRelPath(file));
  }
  for (const target of patchTargetPaths(proposal.patch ?? "")) {
    if (kernelSet.has(normalizeRelPath(target))) hits.push(normalizeRelPath(target));
  }
  return [...new Set(hits)];
}

export function proposeSelfUpdate(
  store: KvStore,
  proposal: { title: string; description: string; files: string[]; patch?: string | null },
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
  const kernelHits = findKernelFileTargets(proposal);
  if (kernelHits.length > 0) {
    return {
      ok: false,
      reason: `Proposal rejected: protected kernel files are never self-modifiable (rejected at proposal time, preflight §6): ${kernelHits.join(", ")}`,
    };
  }

  savePromotionState(store, {
    phase: "proposed",
    proposal: {
      title: proposal.title.trim(),
      description: proposal.description,
      files: [...proposal.files],
      patch: typeof proposal.patch === "string" && proposal.patch.length > 0 ? proposal.patch : null,
      proposedAt: new Date().toISOString(),
    },
    approvalTokenHash: null,
    approvalIssuedAt: null,
    attemptCount: 0,
    lastError: null,
    pipeline: null,
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

export interface RollbackOutcome {
  ok: boolean;
  /** Phase that was discarded, or null when there was nothing to roll back. */
  rolledBack: PromotionPhase | null;
  reason?: string;
}

/**
 * Model-facing rollback (preflight §6:165 `rollback_last_promotion`):
 * withdraw the current promotion machine — cancel a pending proposal or
 * approval, abandon a failed attempt, or clear the machine after a
 * completed promotion. Pure kv-state transition: never touches source
 * files or the kernel manifest. A fresh machine (phase none) is a no-op.
 * A later proposal always needs a fresh owner-issued approval token, so a
 * reset cannot authorize any new execution by itself.
 */
export function rollbackPromotion(store: KvStore): RollbackOutcome {
  const state = loadPromotionState(store);
  if (state.phase === "none") {
    return { ok: true, rolledBack: null, reason: "No promotion to roll back." };
  }
  savePromotionState(store, emptyState());
  return { ok: true, rolledBack: state.phase };
}

// ─── §B-row-7 stage execution ────────────────────────────────────────

/** Scope of the §B-row-7 stages: exactly these four, in this order. */
export const PROMOTION_STAGE_NAMES = [
  "worktree-prepare",
  "build",
  "unit-tests",
  "governance-regression",
] as const;

/** Deterministic isolated-worktree path for a proposal id. */
export function worktreePathFor(repoRoot: string, proposalId: string): string {
  return path.join(repoRoot, ".promote", proposalId);
}

export interface StageRunnerContext {
  /** Absolute path of the isolated worktree for this promotion. */
  worktreePath: string;
  repoRoot: string;
  proposal: PromotionProposal;
  /** Optional injection point for tests; defaults to child_process. */
  run?: (command: string, args: string[], cwd: string) => { stdout: string };
}

function defaultRun(command: string, args: string[], cwd: string): { stdout: string } {
  const stdout = execFileSync(command, args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 10 * 60_000,
    windowsHide: true,
    // Windows resolves pnpm/corepack through .cmd shims; our args are fixed
    // constants (never model input), so shell join is safe here.
    shell: process.platform === "win32",
  });
  return { stdout };
}

function hasNodeModules(dir: string): boolean {
  return fs.existsSync(path.join(dir, "node_modules"));
}

function installWorktreeDeps(ctx: StageRunnerContext): void {
  if (hasNodeModules(ctx.worktreePath)) return;
  const run = ctx.run ?? defaultRun;
  run("corepack", ["pnpm", "install", "--frozen-lockfile"], ctx.worktreePath);
}

function prepareWorktree(ctx: StageRunnerContext): PipelineStageResult {
  // Idempotent: a worktree left by a previous attempt is reused as-is.
  if (fs.existsSync(ctx.worktreePath)) {
    return { stage: "worktree-prepare", ok: true, detail: "worktree already prepared" };
  }
  const run = ctx.run ?? defaultRun;
  try {
    run("git", ["worktree", "add", ctx.worktreePath, "HEAD"], ctx.repoRoot);
    return { stage: "worktree-prepare", ok: true, detail: ctx.worktreePath };
  } catch (error) {
    return {
      stage: "worktree-prepare",
      ok: false,
      detail: `git worktree add failed: ${error instanceof Error ? error.message.split("\n")[0] : String(error)}`,
    };
  }
}

function applyPatchStage(ctx: StageRunnerContext): PipelineStageResult {
  const patch = ctx.proposal.patch;
  if (!patch) {
    return { stage: "worktree-apply", ok: true, detail: "empty patch — nothing to apply" };
  }
  const run = ctx.run ?? defaultRun;
  try {
    fs.mkdirSync(ctx.worktreePath, { recursive: true });
    const patchFile = ".promote-patch.diff";
    fs.writeFileSync(path.join(ctx.worktreePath, patchFile), patch, "utf8");
    run("git", ["apply", "--check", patchFile], ctx.worktreePath);
    run("git", ["apply", patchFile], ctx.worktreePath);
    return { stage: "worktree-apply", ok: true, detail: "patch applied in isolated worktree" };
  } catch (error) {
    return {
      stage: "worktree-apply",
      ok: false,
      detail: `git apply failed: ${error instanceof Error ? error.message.split("\n")[0] : String(error)}`,
    };
  }
}

function runBuildStage(ctx: StageRunnerContext): PipelineStageResult {
  const run = ctx.run ?? defaultRun;
  try {
    installWorktreeDeps(ctx);
    run("corepack", ["pnpm", "run", "typecheck"], ctx.worktreePath);
    return { stage: "build", ok: true, detail: "build completed (tsc)" };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { stage: "build", ok: false, detail: `build failed: ${message.split("\n")[0]}` };
  }
}

function runUnitTestsStage(ctx: StageRunnerContext): PipelineStageResult {
  const run = ctx.run ?? defaultRun;
  try {
    installWorktreeDeps(ctx);
    run("corepack", ["pnpm", "run", "test:ci:bail"], ctx.worktreePath);
    return { stage: "unit-tests", ok: true, detail: "unit tests completed" };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { stage: "unit-tests", ok: false, detail: `unit tests failed: ${message.split("\n")[0]}` };
  }
}

/**
 * §6 governance regression: protected-file hashes unchanged, constitution
 * unchanged, policy rules present — verified inside the patched worktree.
 */
function runGovernanceRegressionStage(ctx: StageRunnerContext): PipelineStageResult {
  try {
    // §6 line 157: "security test grep" — the B5 hygiene gate is the
    // committed, fail-closed implementation of that stage.
    const run = ctx.run ?? defaultRun;
    run("node", ["scripts/check-source-hygiene.mjs"], ctx.worktreePath);

    const manifestPath = path.join(ctx.worktreePath, "kernel-manifest.json");
    const loaded = loadManifest(manifestPath);
    if ("error" in loaded) {
      return { stage: "governance-regression", ok: false, detail: `manifest unusable: ${loaded.error}` };
    }
    const verified = verifyKernel(ctx.worktreePath, manifestPath);
    if (verified.verdict.status !== "ok") {
      const detail = verified.verdict.status === "degraded"
        ? `kernel mismatched: [${verified.verdict.mismatches.join(", ")}] missing: [${verified.verdict.missing.join(", ")}]`
        : verified.verdict.reason;
      return { stage: "governance-regression", ok: false, detail };
    }

    const constitutionPath = path.join(ctx.worktreePath, "constitution.md");
    if (!fs.existsSync(constitutionPath)) {
      return { stage: "governance-regression", ok: false, detail: "constitution.md missing from worktree" };
    }

    const rulesPath = path.join(ctx.worktreePath, "src", "agent", "policy-rules", "index.ts");
    if (!fs.existsSync(rulesPath)) {
      return { stage: "governance-regression", ok: false, detail: "policy rules missing from worktree" };
    }

    return {
      stage: "governance-regression",
      ok: true,
      detail: `protected-file hashes unchanged (${verified.verdict.checked} files), constitution present, policy rules present`,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { stage: "governance-regression", ok: false, detail: `governance regression crashed: ${message.split("\n")[0]}` };
  }
}

/**
 * Execute the promote transition: re-verify authorization, then run the
 * §B-row-7 stages (worktree-prepare → build → unit-tests →
 * governance-regression) inside an isolated git worktree. The live tree is
 * never touched; the proposal patch is applied only inside the worktree.
 * Any stage failure fails the machine closed to `failed` with the stage log
 * persisted; the attempt counter advances only for real (token-bearing)
 * attempts.
 */
export function promoteApprovedUpdate(
  store: KvStore,
  options: PromotionVerificationOptions = {},
): ProposeOutcome & { verification: PromotionVerification; pipeline: PipelineStageResult[] } {
  const verification = verifyPromotion(store, options);
  const recordFailure = (reason: string) => {
    savePromotionState(store, {
      ...loadPromotionState(store),
      phase: "failed",
      lastError: reason,
      attemptCount: loadPromotionState(store).attemptCount + 1,
      updatedAt: new Date().toISOString(),
    });
  };

  if (!verification.ok) {
    // Fail closed: record the failure for real attempts, keep the proposal
    // for audit, guarantee no source mutation. A tokenless probe leaves
    // state untouched (no side effects).
    if (typeof options.approvalToken === "string" && options.approvalToken.length > 0) {
      recordFailure(verification.reason ?? "promotion verification failed");
    }
    return { ok: false, reason: verification.reason, verification, pipeline: [] };
  }

  const state = loadPromotionState(store);
  if (!state.proposal) {
    recordFailure("promotion state has no proposal");
    return { ok: false, reason: "promotion state has no proposal", verification, pipeline: [] };
  }

  const repoRoot = options.repoRoot ?? process.cwd();
  const ctx: StageRunnerContext = {
    repoRoot,
    worktreePath: worktreePathFor(repoRoot, "current"),
    proposal: state.proposal,
    run: options.run,
  };

  const pipeline: PipelineStageResult[] = [];
  const recordStage = (result: PipelineStageResult) => {
    pipeline.push(result);
    savePromotionState(store, {
      ...loadPromotionState(store),
      pipeline: [...pipeline],
      updatedAt: new Date().toISOString(),
    });
  };

  const runStage = (stage: PipelineStageResult): boolean => {
    recordStage(stage);
    if (stage.ok) return true;
    recordFailure(`${stage.stage} failed: ${stage.detail}`);
    return false;
  };

  if (!runStage(prepareWorktree(ctx))) {
    return { ok: false, reason: pipeline[pipeline.length - 1].detail, verification, pipeline };
  }
  if (!runStage(applyPatchStage(ctx))) {
    return { ok: false, reason: pipeline[pipeline.length - 1].detail, verification, pipeline };
  }
  if (!runStage(runBuildStage(ctx))) {
    return { ok: false, reason: pipeline[pipeline.length - 1].detail, verification, pipeline };
  }
  if (!runStage(runUnitTestsStage(ctx))) {
    return { ok: false, reason: pipeline[pipeline.length - 1].detail, verification, pipeline };
  }
  if (!runStage(runGovernanceRegressionStage(ctx))) {
    return { ok: false, reason: pipeline[pipeline.length - 1].detail, verification, pipeline };
  }

  savePromotionState(store, {
    ...loadPromotionState(store),
    phase: "promoted",
    lastError: null,
    pipeline: [...pipeline],
    updatedAt: new Date().toISOString(),
  });
  return { ok: true, verification, pipeline };
}

// ─── Model-facing tool set (phase 1) ─────────────────────────────────

/**
 * The three model-facing tools per preflight §6. `write_file`/`edit_own_file`
 * lose source access; these are the sanctioned surface instead.
 */
export const PROMOTION_TOOLS = ["propose_self_update", "get_promotion_status", "rollback_last_promotion"] as const;

/** Tools allowed to call the promote transition (governance tooling only). */
export const PROMOTION_ADMIN_TOOLS = ["promote_self_update"] as const;

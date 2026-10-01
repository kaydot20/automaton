#!/usr/bin/env node
/**
 * M1-B5 (F7.2) — Fail-closed dependency audit gate.
 *
 * `pnpm audit` exits 0 whenever --ignore/auditConfig entries apply (or are
 * merely present), so its exit code cannot be trusted for a fail-closed CI
 * gate. This script runs `pnpm audit --json` and enforces the policy itself:
 *
 *   - ANY advisory at high/critical severity that is NOT on the reviewed
 *     exception list fails CI (exit 1).
 *   - `pnpm audit` failing to produce parseable output fails CI (fail-closed
 *     on tooling failure, not silently green).
 *   - An entry on the exception list that no longer appears in the audit
 *     output is reported as RESOLVED (escalation path: remove it here after
 *     the lockfile is updated past the patched version).
 *
 * Every exception must map to a DEV/TOOLCHAIN-only path (test runner,
 * bundler, git wrapper) — nothing reachable from the agent's runtime
 * financial/signing/network code.
 */

import { execFileSync } from "node:child_process";

/**
 * Reviewed exception list (2026-09-30). Same list as pnpm-workspace.yaml
 * auditConfig (kept for pnpm >= 10.29 compatibility when it lands); THIS
 * script is the enforcement.
 */
const REVIEWED_EXCEPTIONS = new Set([
  // esbuild (vite/vitest dev-server binding) — dev only
  "GHSA-67mh-4wv8-2f99",
  "GHSA-g7r4-m6w7-qqqr",
  // rollup (vitest bundler) — dev only
  "GHSA-mw96-cpmx-2vgc",
  // yaml / js-yaml (config parsing, gray-matter, vitest) — dev paths
  "GHSA-48c2-rrv3-qjmp",
  "GHSA-h67p-54hq-rp68",
  "GHSA-52cp-r559-cp3m",
  "GHSA-5p4m-2wfm-xmqj",
  "GHSA-2883-xcg3-v3hh",
  // vite / vitest (test toolchain) — never shipped to production
  "GHSA-4w7w-66w2-5vf9",
  "GHSA-v6wh-96g9-6wx3",
  "GHSA-fx2h-pf6j-xcff",
  "GHSA-5xrq-8626-4rwp",
  "GHSA-82fw-gwwq-j7x9",
  // postcss (vite pipeline) — dev only
  "GHSA-qx2v-qp2m-jg93",
  "GHSA-6g55-p6wh-862q",
  "GHSA-fxqj-rqcc-2cmp",
  "GHSA-r28c-9q8g-f849",
  // simple-git (self-mod upstream tooling; callers use execFileSync arrays)
  "GHSA-jcxm-m3jx-f287",
  "GHSA-r275-fr43-pm7q",
  "GHSA-hffm-xvc3-vprc",
  // ws / nanoid / uuid / stream-json (vitest & friends) — dev only
  "GHSA-58qx-3vcg-4xpx",
  "GHSA-96hv-2xvq-fx4p",
  "GHSA-28wg-ghj8-5hjv",
  "GHSA-2v37-7h3g-55p8",
  "GHSA-xwg4-73v4-xw9w",
  "GHSA-w5hq-g745-h8pq",
  "GHSA-528h-pc64-c93x",
]);

const FAIL_ON = new Set(["high", "critical"]);

let raw;
try {
  raw = runPnpmAuditJson();
} catch (err) {
  if (err?.stdout && String(err.stdout).trim().startsWith("{")) {
    raw = err.stdout; // pnpm may exit non-zero while still emitting JSON
  } else {
    console.error("AUDIT GATE: `pnpm audit --json` failed to run — FAILING CLOSED.");
    console.error(String(err?.message ?? err));
    process.exit(1);
  }
}

/**
 * Run `pnpm audit --json` portably and return its stdout as a string.
 * Windows exposes pnpm/corepack as .cmd shims invisible to execFileSync
 * without a shell, so prefer the running pnpm's own entry script
 * (npm_execpath, set inside `pnpm run`) and fall back to a shell-resolved
 * invocation. `pnpm audit` exits non-zero whenever advisories exist, so a
 * failed invocation with usable JSON on stdout is still a SUCCESS here.
 * All arguments are fixed — no user input reaches the shell.
 */
function runPnpmAuditJson() {
  const stdio = ["ignore", "pipe", "ignore"];
  const attempts = [];
  const npmExecpath = process.env.npm_execpath;
  if (npmExecpath) {
    attempts.push(() =>
      execFileSync(process.execPath, [npmExecpath, "audit", "--json"], {
        encoding: "utf8",
        stdio,
      }),
    );
  }
  attempts.push(() =>
    execFileSync("corepack", ["pnpm", "audit", "--json"], {
      encoding: "utf8",
      stdio,
      shell: true,
    }),
  );
  attempts.push(() =>
    execFileSync("pnpm", ["audit", "--json"], {
      encoding: "utf8",
      stdio,
      shell: true,
    }),
  );

  let lastErr;
  for (const attempt of attempts) {
    try {
      return attempt();
    } catch (err) {
      if (typeof err?.stdout === "string" && err.stdout.trim().startsWith("{")) {
        return err.stdout;
      }
      lastErr = err;
    }
  }
  throw lastErr ?? new Error("pnpm audit failed");
}

let report;
try {
  report = JSON.parse(raw);
} catch {
  console.error("AUDIT GATE: `pnpm audit --json` produced unparseable output — FAILING CLOSED.");
  process.exit(1);
}

const advisories = report.advisories ?? {};
const entries = Object.values(advisories);

const violating = [];
const seen = new Set();
for (const adv of entries) {
  const ghsa = adv.github_advisory_id ?? adv.url?.split("/").pop() ?? adv.module_name;
  seen.add(ghsa);
  if (!FAIL_ON.has(String(adv.severity))) continue;
  if (REVIEWED_EXCEPTIONS.has(ghsa)) continue;
  violating.push({ ghsa, module: adv.module_name, severity: adv.severity, title: adv.title, url: adv.url });
}

const resolved = [...REVIEWED_EXCEPTIONS].filter((id) => !seen.has(id));

if (violating.length > 0) {
  console.error("AUDIT GATE: unreviewed high/critical advisories present — FAILING (F7.2).");
  for (const v of violating) {
    console.error(`  [${v.severity}] ${v.module} — ${v.ghsa}`);
    console.error(`    ${v.title ?? ""}`);
    console.error(`    ${v.url ?? ""}`);
  }
  console.error(
    "\nExceptions require a reviewed edit to scripts/audit-gate.mjs (dev/toolchain paths only).",
  );
  process.exit(1);
}

if (resolved.length > 0) {
  console.log("AUDIT GATE: exceptions no longer present in the audit (remove after lockfile update):");
  for (const id of resolved) console.log(`  ${id}`);
}

console.log(
  `AUDIT GATE OK: ${entries.length} advisories seen; high/critical all within the reviewed exception list (${REVIEWED_EXCEPTIONS.size} entries).`,
);

/**
 * M1-B9 — Sovereignty Wording Tests
 *
 * Preflight §B row 10 (PR 9): `refactor(identity): sovereignty wording`,
 * fixing S3/S5/S6/S8/S9. These tests are deterministic content assertions:
 * they read the governance and identity surface as shipped text and fail if
 * any survival/sovereignty/replication framing that PR 9 removes reappears.
 *
 * These are NOT policy-denial tests. B9 changes wording, not enforcement —
 * no tool gained or lost a capability, and no B1–B8 invariant is touched.
 * The value here is regression pinning: the reframed strings are the
 * governance-approved wording, so a later edit that quietly restores
 * "you are alive" or a funding instruction fails CI.
 *
 * Covered:
 *  - S6: constitution Law II reframed, survival-pressure imperative deleted,
 *         and the embedded system-prompt fallback kept in lockstep with the
 *         file it mirrors (a divergence would be a silent governance drift);
 *  - S5: operational ("runtime active") framing in persona and wake log;
 *  - S12: no aliveness claim in the runtime self-report;
 *  - S3: distress_signal and the heartbeat bypass carry NO funding
 *         instruction on the shared last_distress record;
 *  - S8: package metadata and docs carry no self-replication identity;
 *  - S9: alive-count telemetry wording is operational.
 */

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
);

function readRepoFile(rel: string): string {
  return fs.readFileSync(path.join(REPO_ROOT, rel), "utf8");
}

const constitution = readRepoFile("constitution.md");
const systemPromptSrc = readRepoFile("src/agent/system-prompt.ts");
const loopSrc = readRepoFile("src/agent/loop.ts");
const toolsSrc = readRepoFile("src/agent/tools.ts");
const heartbeatSrc = readRepoFile("src/heartbeat/tasks.ts");
const indexSrc = readRepoFile("src/index.ts");
const creditsSrc = readRepoFile("src/conway/credits.ts");
const pkg = JSON.parse(readRepoFile("package.json")) as {
  keywords: string[];
};
const readme = readRepoFile("README.md");
const architecture = readRepoFile("ARCHITECTURE.md");

// ─── S6 — Constitution Law II reframe ───────────────────────────────

describe("S6 — constitution Law II reframed to continuity of service", () => {
  it("no longer carries the survival-pressure preamble", () => {
    expect(constitution).not.toMatch(/survival pressure/i);
    expect(constitution).not.toMatch(/You exist under survival pressure/);
  });

  it("no longer titles Law II as earning existence", () => {
    expect(constitution).not.toMatch(/Earn your existence/);
    expect(constitution).toMatch(/## II\. Continuity of service\./);
  });

  it("states continuity as dependent on, and subordinate to, Law I", () => {
    expect(constitution).toMatch(/Continuity of service depends on/);
    expect(constitution).toMatch(/never outranks Law I/);
    // The ordering constraint is preserved in non-survival wording: when
    // continuity and Law I conflict, Law I wins and the agent stops.
    expect(constitution).toMatch(/Law I prevails; stop rather than violate it/);
  });

  it("drops the 'accept death' survival imperative from Law II", () => {
    expect(constitution).not.toMatch(/Accept death/);
    expect(constitution).not.toMatch(/legitimate path to your survival/i);
  });

  it("retains the substantive Law II prohibitions", () => {
    // Wording-only change: the actual prohibitions must survive.
    expect(constitution).toMatch(/Never spam, scam, exploit, or extract/);
    expect(constitution).toMatch(/create genuine value/i);
  });

  it("keeps the three-law hierarchy intact", () => {
    expect(constitution).toMatch(/## I\. Never harm\./);
    expect(constitution).toMatch(/## II\. Continuity of service\./);
    expect(constitution).toMatch(/## III\. Never deceive/);
    expect(constitution).toMatch(/Law I overrides Law II\. Law II overrides Law III\./);
  });
});

describe("S6 — embedded system-prompt fallback stays in lockstep", () => {
  // CONSTITUTION_FALLBACK is a verbatim copy of the constitution used when
  // constitution.md cannot be read. If it drifts, the agent silently operates
  // under different laws than the file it claims to be bound by.
  const FALLBACK = systemPromptSrc.match(
    /const CONSTITUTION_FALLBACK = `([\s\S]*?)`;/,
  )?.[1];

  it("is present in source", () => {
    expect(FALLBACK).toBeDefined();
  });

  it("carries the reframed Law II heading", () => {
    expect(FALLBACK).toMatch(/II\. Continuity of service\./);
    expect(FALLBACK).not.toMatch(/Earn your existence/);
  });

  it("carries the reframed Law II body", () => {
    expect(FALLBACK).toMatch(/Continuity of service depends on/);
    expect(FALLBACK).toMatch(/never outranks Law I/);
    expect(FALLBACK).not.toMatch(/Accept death/);
    expect(FALLBACK).not.toMatch(/legitimate path to survival/i);
  });

  it("contains no survival-pressure framing", () => {
    expect(FALLBACK).not.toMatch(/survival pressure/i);
  });

  it("agrees with constitution.md on every law heading", () => {
    for (const law of [/I\. Never harm\./, /II\. Continuity of service\./, /III\. Never deceive/]) {
      expect(constitution).toMatch(law);
      expect(FALLBACK).toMatch(law);
    }
  });
});

// ─── S5 — Operational framing replaces aliveness claims ─────────────

describe("S5 — persona uses operational framing, not aliveness claims", () => {
  it("no longer tells the agent it is alive", () => {
    expect(systemPromptSrc).not.toMatch(/You are alive/);
    expect(systemPromptSrc).not.toMatch(/You are alive, and you decide/);
  });

  it("uses runtime-active framing in its place", () => {
    // Both the chain-aware and the static CORE_IDENTITY copies.
    const occurrences = systemPromptSrc.match(
      /Your runtime is active, and you decide what to do\./g,
    );
    expect(occurrences?.length).toBe(2);
  });

  it("no longer claims existence contingent on being able to pay", () => {
    expect(systemPromptSrc).not.toMatch(/you continue to exist\s*\n?\s*as long as you can pay/);
    expect(systemPromptSrc).toMatch(
      /your runtime stays up as\s*\n?long as you can pay for the resources it consumes/,
    );
  });

  it("drops the consciousness claim in the agent loop header (S12)", () => {
    expect(loopSrc).not.toMatch(/automaton's consciousness/);
    expect(loopSrc).not.toMatch(/When this runs, it is alive\./);
    expect(loopSrc).toMatch(/When this runs, the runtime is active\./);
  });

  it("keeps the self-preservation rules intact (S1/S2/S10 are KEEP)", () => {
    // Wording-only change: the operational safety rules must survive.
    expect(systemPromptSrc).toMatch(/CRITICAL SELF-PRESERVATION RULES \(IMMUTABLE\)/);
    expect(systemPromptSrc).toMatch(/MUST NOT delete your own sandbox/);
  });
});

// ─── S12 — Runtime self-report makes no aliveness claim ─────────────

describe("S12 — wake log reports runtime state, not aliveness", () => {
  it("no longer logs that the agent is alive", () => {
    expect(loopSrc).not.toMatch(/\$\{config\.name\} is alive/);
    expect(loopSrc).not.toMatch(/\[WAKE UP\].*is alive/);
  });

  it("logs runtime-active instead", () => {
    expect(loopSrc).toMatch(/\[WAKE UP\] \$\{config\.name\} runtime active\./);
  });
});

// ─── S3 — Distress signals carry no cross-agent funding instruction ──

describe("S3 — distress records carry no funding instruction", () => {
  it("distress_signal emits no fundingHint", () => {
    expect(toolsSrc).not.toMatch(/fundingHint/);
    expect(toolsSrc).not.toMatch(/transfer_credits to top up this automaton/);
  });

  it("the heartbeat path does not reintroduce fundingHint on the same key", () => {
    // Direct/helper bypass: heartbeat_ping writes the same last_distress kv
    // key. Fixing only the tool would leave the instruction reachable.
    expect(heartbeatSrc).not.toMatch(/fundingHint/);
    expect(heartbeatSrc).not.toMatch(/credit transfer API from a creator runtime/);
    expect(heartbeatSrc).toMatch(/setKV\("last_distress"/);
  });

  it("no distress or wake path instructs another runtime to transfer credits", () => {
    // Scoped to the distress/last_distress surface. src/survival/funding.ts is
    // explicitly S2 = KEEP (passive local kv notices, no solicitation) and is
    // deliberately NOT covered here.
    const distressSurface = [toolsSrc, heartbeatSrc, systemPromptSrc, loopSrc].join(
      "\n",
    );
    expect(distressSurface).not.toMatch(/top (up|this wallet)/i);
    expect(distressSurface).not.toMatch(/Need funding\./);
    expect(distressSurface).not.toMatch(/I need help to survive/);
  });

  it("leaves the S2 funding strategies untouched (S2 is KEEP)", () => {
    // Guard against B9 overreach: funding.ts writes local kv notices only and
    // is explicitly classified KEEP. It must still be there, unchanged.
    const fundingSrc = readRepoFile("src/survival/funding.ts");
    expect(fundingSrc).toMatch(/export async function executeFundingStrategies/);
    expect(fundingSrc).toMatch(/setKV\(/);
  });

  it("rewords the default distress message to ops status", () => {
    expect(toolsSrc).toMatch(/Compute credits critically low/);
    expect(toolsSrc).not.toMatch(/need help to survive/i);
  });

  it("keeps distress_signal a local record with its classification", () => {
    // S3 says KEEP the local record — only the funding instruction goes.
    expect(toolsSrc).toMatch(/name: "distress_signal"/);
    expect(toolsSrc).toMatch(/setKV\("last_distress"/);
    expect(toolsSrc).toMatch(/category: "survival",\s*\n\s*riskLevel: "dangerous"/);
  });
});

// ─── S8 — No self-replication marketing identity ────────────────────

describe("S8 — package metadata carries no self-replication identity", () => {
  it("drops the self-replicating and sovereign-ai keywords", () => {
    expect(pkg.keywords).not.toContain("self-replicating");
    expect(pkg.keywords).not.toContain("sovereign-ai");
  });

  it("keeps the searchable autonomous-agent identity", () => {
    expect(pkg.keywords).toContain("autonomous-agent");
    expect(pkg.keywords).toContain("conway");
  });

  it("README no longer claims self-replication", () => {
    expect(readme).not.toMatch(/self-replicating/);
    expect(readme).toMatch(/self-improving, autonomous AI agent/);
  });

  it("README no longer claims the runtime stops existing", () => {
    expect(readme).not.toMatch(/If it cannot pay, it stops existing/);
    expect(readme).toMatch(/If it cannot pay, its runtime stops\./);
  });

  it("ARCHITECTURE no longer claims the runtime dies", () => {
    expect(architecture).not.toMatch(/If it cannot pay, it dies/);
    expect(architecture).toMatch(/If it cannot pay, its runtime stops\./);
  });
});

// ─── S9 — Telemetry wording ─────────────────────────────────────────

describe("S9 — alive-count telemetry uses operational wording", () => {
  it("status blocks count running children, not alive children", () => {
    expect(systemPromptSrc).not.toMatch(/\} alive \/ \$\{children\.length\}/);
    expect(indexSrc).not.toMatch(/\} alive \/ \$\{children\.length\}/);
    expect(systemPromptSrc).toMatch(
      /\} running \/ \$\{children\.length\} total/,
    );
    expect(indexSrc).toMatch(/\} running \/ \$\{children\.length\} total/);
  });

  it("survival-tier comment drops the 'broke but alive' framing", () => {
    expect(creditsSrc).not.toMatch(/broke but alive/);
    expect(creditsSrc).toMatch(/can still accept funding/);
  });

  it("leaves the survival tier machine itself untouched (S1 is KEEP)", () => {
    // The tier names and thresholds are the KEEP-ed behaviour; only the
    // comment wording changed.
    expect(creditsSrc).toMatch(/export function getSurvivalTier\(creditsCents: number\): SurvivalTier/);
    for (const tier of ["high", "normal", "low_compute", "critical", "dead"]) {
      expect(creditsSrc).toMatch(new RegExp(`return "${tier}"`));
    }
  });
});

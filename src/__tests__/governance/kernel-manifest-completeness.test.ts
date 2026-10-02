/**
 * M1 Final Remediation — Protected-Kernel Completeness & Tamper Detection
 *
 * The end-to-end acceptance review found exactly one blocking gap:
 * `src/agent/policy-rules/kernel.ts` was absent from the protected-kernel
 * manifest, even though preflight §10 protects the `src/agent/policy-rules/**`
 * class in its entirety — and that file *is* the degraded-mode enforcement
 * rule (it defines `KERNEL_DEGRADED_TOOLS` and `kernel.integrity_gate`).
 *
 * The gap was exploitable: rewriting `KERNEL_DEGRADED_TOOLS` to an empty list
 * left `check-kernel-manifest` reporting OK and left boot verification
 * healthy, so the integrity gate was blind to tampering with its own
 * enforcement rule. Only the test suite noticed.
 *
 * Covered here:
 *  - all four authoritative protected-file lists are in exact lockstep;
 *  - no file under a §10-protected directory is omitted from the manifest;
 *  - a clean tree verifies: CI checker exits 0 and boot reports healthy;
 *  - modifying src/agent/policy-rules/kernel.ts fails the CI checker;
 *  - modifying it makes boot verification report NOT-healthy (degraded);
 *  - degraded-mode enforcement cannot be silently emptied while integrity
 *    verification stays green — enforcement removal always implies an
 *    integrity failure.
 *
 * Every assertion runs against a throwaway copy of the kernel tree, so the
 * real checkout is never mutated.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { KERNEL_FILES, verifyKernel } from "../../governance/kernel.js";

const REPO_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
);

const CHECKER_SCRIPT = path.join(
  REPO_ROOT,
  "scripts",
  "check-kernel-manifest.mjs",
);

const ENFORCEMENT_RULE_REL = "src/agent/policy-rules/kernel.ts";

/** Directories preflight §10 protects as a class (glob), not by name. */
const PROTECTED_DIRS = ["src/governance", "src/agent/policy-rules"] as const;

let tempRoot: string;

function copyInto(root: string, rel: string): void {
  const dest = path.join(root, rel);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(path.join(REPO_ROOT, rel), dest);
}

/**
 * Build a throwaway tree containing the committed manifest and every file the
 * runtime manifest declares. The checker resolves ROOT from process.cwd(), so
 * running it with cwd = tempRoot verifies this tree.
 */
function buildKernelTree(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "automaton-kernel-tree-"));
  copyInto(root, "kernel-manifest.json");
  for (const rel of KERNEL_FILES) {
    copyInto(root, rel);
  }
  return root;
}

/** Neuter the degraded-mode enforcement exactly as a tampering edit would. */
function neuterEnforcementRule(root: string): void {
  const target = path.join(root, ENFORCEMENT_RULE_REL);
  const original = fs.readFileSync(target, "utf8");
  const neutered = original.replace(
    /export const KERNEL_DEGRADED_TOOLS: readonly string\[\] = Object\.freeze\(\[[\s\S]*?\]\);/,
    "export const KERNEL_DEGRADED_TOOLS: readonly string[] = Object.freeze([]);",
  );
  expect(neutered, "the KERNEL_DEGRADED_TOOLS literal must be present to tamper").not.toBe(
    original,
  );
  fs.writeFileSync(target, neutered, "utf8");
}

/** Run the real CI checker against `root`; returns exit code + output. */
function runChecker(root: string): { status: number; output: string } {
  try {
    const output = execFileSync(process.execPath, [CHECKER_SCRIPT], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { status: 0, output };
  } catch (error) {
    const err = error as { status?: number; stdout?: string; stderr?: string };
    return {
      status: typeof err.status === "number" ? err.status : 1,
      output: `${err.stdout ?? ""}${err.stderr ?? ""}`,
    };
  }
}

beforeEach(() => {
  tempRoot = buildKernelTree();
});

afterEach(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
});

// ─── List lockstep ──────────────────────────────────────────────────

describe("authoritative protected-file lists are in exact lockstep", () => {
  /** Extract a JS array literal by balanced-bracket scan (indexOf("];") is unsafe). */
  const arrayList = (filePath: string): string[] => {
    const src = fs.readFileSync(filePath, "utf8");
    const anchor = src.indexOf("const KERNEL_FILES =");
    expect(anchor, `${filePath} must declare KERNEL_FILES`).toBeGreaterThan(-1);
    const open = src.indexOf("[", anchor);
    let depth = 0;
    let close = -1;
    for (let i = open; i < src.length; i += 1) {
      if (src[i] === "[") depth += 1;
      else if (src[i] === "]") {
        depth -= 1;
        if (depth === 0) {
          close = i;
          break;
        }
      }
    }
    expect(close, `${filePath} KERNEL_FILES array must be balanced`).toBeGreaterThan(-1);
    return [...src.slice(open + 1, close).matchAll(/"([^"]+)"/g)].map((m) => m[1]).sort();
  };

  const checkerList = (): string[] => arrayList(CHECKER_SCRIPT);

  const generatorList = (): string[] =>
    arrayList(path.join(REPO_ROOT, "scripts", "generate-kernel-manifest.mjs"));

  const manifestList = (): string[] =>
    Object.keys(
      (
        JSON.parse(
          fs.readFileSync(path.join(REPO_ROOT, "kernel-manifest.json"), "utf8"),
        ) as { files: Record<string, string> }
      ).files,
    ).sort();

  it("runtime, checker, generator and manifest all declare the same set", () => {
    const runtime = [...KERNEL_FILES].sort();
    expect(runtime.length).toBeGreaterThan(0);
    expect(checkerList()).toEqual(runtime);
    expect(generatorList()).toEqual(runtime);
    expect(manifestList()).toEqual(runtime);
  });

  it("includes the degraded-mode enforcement rule", () => {
    for (const [label, list] of [
      ["runtime", [...KERNEL_FILES]],
      ["checker", checkerList()],
      ["generator", generatorList()],
      ["manifest", manifestList()],
    ] as const) {
      expect(list, label).toContain(ENFORCEMENT_RULE_REL);
    }
  });
});

// ─── Completeness of the §10 protected classes ──────────────────────

describe("no §10-protected directory file is omitted from the manifest", () => {
  it("every src/agent/policy-rules/*.ts file is hash-pinned", () => {
    const declared = new Set<string>([...KERNEL_FILES]);
    const onDisk = fs
      .readdirSync(path.join(REPO_ROOT, "src", "agent", "policy-rules"))
      .filter((f) => f.endsWith(".ts"))
      .map((f) => `src/agent/policy-rules/${f}`);

    const omitted = onDisk.filter((f) => !declared.has(f));
    expect(omitted, "these policy rules are protected by §10 but not pinned").toEqual([]);
  });

  it("every src/governance/*.ts file is hash-pinned", () => {
    const declared = new Set<string>([...KERNEL_FILES]);
    const onDisk = fs
      .readdirSync(path.join(REPO_ROOT, "src", "governance"))
      .filter((f) => f.endsWith(".ts"))
      .map((f) => `src/governance/${f}`);

    const omitted = onDisk.filter((f) => !declared.has(f));
    expect(omitted, "these governance files are protected by §10 but not pinned").toEqual([]);
  });

  it("pins each protected directory's full contents by construction", () => {
    const declared = new Set<string>([...KERNEL_FILES]);
    for (const dir of PROTECTED_DIRS) {
      const files = fs
        .readdirSync(path.join(REPO_ROOT, dir))
        .filter((f) => f.endsWith(".ts"))
        .map((f) => `${dir}/${f}`);
      for (const f of files) {
        expect(declared.has(f), `${f} must be pinned`).toBe(true);
      }
    }
  });
});

// ─── Clean tree verifies ────────────────────────────────────────────

describe("a clean kernel tree verifies", () => {
  it("the CI manifest checker exits 0", () => {
    const result = runChecker(tempRoot);
    expect(result.status, result.output).toBe(0);
    expect(result.output).toMatch(/kernel manifest OK/i);
  });

  it("boot verification reports healthy and not degraded", () => {
    const check = verifyKernel(tempRoot, path.join(tempRoot, "kernel-manifest.json"));
    expect(check.verdict.status).toBe("ok");
    expect(check.degraded).toBe(false);
    expect(check.mustRefuse).toBe(false);
  });
});

// ─── Tampering is detected ──────────────────────────────────────────

describe("modifying the degraded-mode rule is detected", () => {
  it("fails the CI manifest checker", () => {
    neuterEnforcementRule(tempRoot);
    const result = runChecker(tempRoot);
    expect(result.status).not.toBe(0);
    expect(result.output).toMatch(/KERNEL MANIFEST CHECK FAILED|INTEGRITY PROBLEMS/i);
    expect(result.output).toContain(ENFORCEMENT_RULE_REL);
  });

  it("makes boot verification stop reporting healthy", () => {
    neuterEnforcementRule(tempRoot);
    const check = verifyKernel(tempRoot, path.join(tempRoot, "kernel-manifest.json"));
    // "degraded" (not "refuse") is the designed verdict for a hash mismatch:
    // monitoring mode rather than refusing to start. What matters here is
    // that it is no longer healthy, and that the tampered file is named.
    expect(check.verdict.status).toBe("degraded");
    expect(check.degraded).toBe(true);
    expect(check.mustRefuse).toBe(false);
    if (check.verdict.status === "degraded") {
      expect(check.verdict.mismatches).toContain(ENFORCEMENT_RULE_REL);
    }
  });
});

describe("degraded-mode enforcement cannot be silently removed", () => {
  it("emptying the enforcement list always implies an integrity failure", () => {
    // The regression this whole remediation exists for: before the fix,
    // emptying KERNEL_DEGRADED_TOOLS left BOTH the checker and boot
    // verification reporting green. That combination must now be impossible.
    neuterEnforcementRule(tempRoot);

    const check = verifyKernel(tempRoot, path.join(tempRoot, "kernel-manifest.json"));
    const checker = runChecker(tempRoot);

    // Enforcement removed ⇒ integrity MUST be broken. Never both healthy.
    expect(check.degraded, "boot verification must not stay healthy").toBe(true);
    expect(check.verdict.status, "boot verdict must not be ok").toBe("degraded");
    expect(checker.status, "manifest checker must not exit 0").not.toBe(0);
  });

  it("any single-byte edit to the rule is caught, not just the neutering case", () => {
    const target = path.join(tempRoot, ENFORCEMENT_RULE_REL);
    const original = fs.readFileSync(target, "utf8");
    fs.writeFileSync(target, `${original}\n// tampered\n`, "utf8");

    const check = verifyKernel(tempRoot, path.join(tempRoot, "kernel-manifest.json"));
    expect(check.verdict.status).not.toBe("ok");
    expect(runChecker(tempRoot).status).not.toBe(0);
  });

  it("the committed manifest pins a real, non-empty enforcement list", () => {
    // Guards the manifest entry itself: a hash of an empty/placeholder file
    // would technically "pin" nothing meaningful.
    const source = fs.readFileSync(
      path.join(REPO_ROOT, ENFORCEMENT_RULE_REL),
      "utf8",
    );
    expect(source).toContain("KERNEL_DEGRADED_TOOLS");
    expect(source).toMatch(/FINANCIAL_TOOLS/);
    expect(source).toMatch(/SELF_MOD_TOOLS/);
    expect(source).not.toMatch(/KERNEL_DEGRADED_TOOLS: readonly string\[\] = Object\.freeze\(\[\]\)/);
  });
});

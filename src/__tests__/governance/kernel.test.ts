/**
 * M1-B6 — Protected Kernel Integrity Tests
 *
 * Covers the preflight §10 acceptance matrix:
 *  - valid state verifies OK;
 *  - modified protected file → degraded + policy denial (hash mismatch);
 *  - missing protected file → degraded + policy denial;
 *  - kernel file present on disk but absent from manifest → mismatch
 *    (unexpected/extra kernel file);
 *  - malformed manifest (bad JSON, wrong algorithm, non-digest entry,
 *    empty files, path traversal) → refuse;
 *  - startup refusal happens before autonomous execution (mustRefuse);
 *  - degraded mode denies financial/spawn/self-mod tools through the real
 *    policy rule set, and re-allows them once integrity is restored;
 *  - escalation records persist to kv and deduplicate;
 *  - manifest generation is deterministic and EOL-stable;
 *  - the runtime never regenerates the manifest (verification is read-only).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type Database from "better-sqlite3";
import {
  KERNEL_FILES,
  KERNEL_ESCALATION_KEY,
  defaultManifestPath,
  generateManifest,
  hashKernelFiles,
  isKernelDegraded,
  loadManifest,
  readKernelEscalation,
  recordKernelEscalation,
  serializeManifest,
  setKernelDegraded,
  verifyKernel,
} from "../../governance/kernel.js";
import { createKernelIntegrityRule } from "../../agent/policy-rules/kernel.js";
import { createDefaultRules } from "../../agent/policy-rules/index.js";
import { PolicyEngine } from "../../agent/policy-engine.js";
import type { PolicyRequest } from "../../types.js";

const REPO_ROOT = path.resolve(__dirname, "../../..");
const MANIFEST_PATH = defaultManifestPath(REPO_ROOT);

// ─── Test tree helpers ───────────────────────────────────────────────

function makeTmpRoot(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "kernel-test-"));
}

/** Materialize the real kernel file set (plus manifest) into a tmp tree. */
function copyKernelTree(root: string): void {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8")) as {
    files: Record<string, string>;
  };
  for (const rel of Object.keys(manifest.files)) {
    const source = path.join(REPO_ROOT, rel);
    const target = path.join(root, rel);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(source, target);
  }
  fs.copyFileSync(MANIFEST_PATH, path.join(root, "kernel-manifest.json"));
}

function writeManifest(root: string, content: unknown): string {
  const manifestPath = path.join(root, "kernel-manifest.json");
  fs.writeFileSync(
    manifestPath,
    typeof content === "string" ? content : JSON.stringify(content, null, 2),
    "utf8",
  );
  return manifestPath;
}

function makeRequest(toolName: string): PolicyRequest {
  return {
    tool: {
      name: toolName,
      description: "test tool",
      category: "financial",
      riskLevel: "dangerous",
    },
    args: {},
    context: {} as PolicyRequest["context"],
    turnContext: {
      inputSource: "agent",
      turnToolCallCount: 0,
      sessionSpend: {} as PolicyRequest["turnContext"]["sessionSpend"],
    },
  };
}

beforeEach(() => {
  setKernelDegraded(false);
});

afterEach(() => {
  setKernelDegraded(false);
});

// ─── 1. Valid state ─────────────────────────────────────────────────

describe("kernel integrity — valid state", () => {
  it("the committed manifest is structurally valid", () => {
    const loaded = loadManifest(MANIFEST_PATH);
    expect(loaded).toHaveProperty("manifest");
    if ("manifest" in loaded) {
      expect(loaded.manifest.algorithm).toBe("sha256");
      expect(Object.keys(loaded.manifest.files).sort()).toEqual([...KERNEL_FILES].sort());
    }
  });

  it("verifies OK against the pristine tree", () => {
    const result = verifyKernel(REPO_ROOT, MANIFEST_PATH);
    expect(result.verdict.status).toBe("ok");
    expect(result.degraded).toBe(false);
    expect(result.mustRefuse).toBe(false);
    if (result.verdict.status === "ok") {
      expect(result.verdict.checked).toBe(KERNEL_FILES.length);
    }
  });

  it("hashes are EOL-stable (CRLF and LF content hash identically)", () => {
    const root = makeTmpRoot();
    try {
      copyKernelTree(root);
      // Rewrite every kernel file with CRLF endings; hashes must not change.
      const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8")) as {
        files: Record<string, string>;
      };
      for (const rel of Object.keys(manifest.files)) {
        const target = path.join(root, rel);
        const content = fs.readFileSync(target, "utf8");
        fs.writeFileSync(target, content.replace(/\n/g, "\r\n").replace(/\r\r\n/g, "\r\n"), "utf8");
      }
      const result = verifyKernel(root, path.join(root, "kernel-manifest.json"));
      expect(result.verdict.status).toBe("ok");
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("manifest generation is deterministic (sorted, stable serialization)", () => {
    const first = serializeManifest(generateManifest(REPO_ROOT));
    const second = serializeManifest(generateManifest(REPO_ROOT));
    expect(first).toBe(second);
    expect(first.endsWith("\n")).toBe(true);
    const keys = JSON.parse(first).files as Record<string, string>;
    expect(Object.keys(keys)).toEqual([...Object.keys(keys)].sort());
  });
});

// ─── 2/3/4. Modified, missing, unexpected kernel files ───────────────

describe("kernel integrity — tampered, missing, and unexpected files", () => {
  it("modified protected file → degraded with hash mismatch", () => {
    const root = makeTmpRoot();
    try {
      copyKernelTree(root);
      const target = path.join(root, "constitution.md");
      fs.writeFileSync(target, `${fs.readFileSync(target, "utf8")}\n<!-- tampered -->\n`, "utf8");

      const result = verifyKernel(root, path.join(root, "kernel-manifest.json"));
      expect(result.verdict.status).toBe("degraded");
      expect(result.degraded).toBe(true);
      expect(result.mustRefuse).toBe(false);
      if (result.verdict.status === "degraded") {
        expect(result.verdict.mismatches).toContain("constitution.md");
        expect(result.verdict.missing).toEqual([]);
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("missing protected file → degraded (fail closed, not thrown away)", () => {
    const root = makeTmpRoot();
    try {
      copyKernelTree(root);
      fs.rmSync(path.join(root, "src", "agent", "injection-defense.ts"));

      const result = verifyKernel(root, path.join(root, "kernel-manifest.json"));
      expect(result.verdict.status).toBe("degraded");
      expect(result.degraded).toBe(true);
      if (result.verdict.status === "degraded") {
        expect(result.verdict.missing).toContain("src/agent/injection-defense.ts");
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("kernel file on disk but absent from manifest → mismatch (extra file)", () => {
    const root = makeTmpRoot();
    try {
      copyKernelTree(root);
      const manifest = JSON.parse(
        fs.readFileSync(path.join(root, "kernel-manifest.json"), "utf8"),
      ) as { files: Record<string, string> };
      delete manifest.files["src/net/policy.ts"];
      writeManifest(root, manifest);

      const result = verifyKernel(root, path.join(root, "kernel-manifest.json"));
      expect(result.verdict.status).toBe("degraded");
      if (result.verdict.status === "degraded") {
        expect(result.verdict.mismatches).toContain("src/net/policy.ts");
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("hashKernelFiles reports missing files without throwing", () => {
    const root = makeTmpRoot();
    try {
      copyKernelTree(root);
      fs.rmSync(path.join(root, "src", "conway", "credits.ts"));
      const entries = hashKernelFiles(root);
      expect(entries.get("src/conway/credits.ts")?.exists).toBe(false);
      expect(entries.get("src/conway/credits.ts")?.hash).toBeNull();
      expect(entries.get("constitution.md")?.exists).toBe(true);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

// ─── 5. Malformed manifests → refuse ─────────────────────────────────

describe("kernel integrity — malformed manifests fail closed", () => {
  const cases: Array<[string, string | unknown]> = [
    ["invalid JSON", "{ not json at all"],
    ["wrong algorithm", { algorithm: "md5", files: { "constitution.md": "a".repeat(64) } }],
    ["non-digest entry", { algorithm: "sha256", files: { "constitution.md": "deadbeef" } }],
    ["empty files", { algorithm: "sha256", files: {} }],
    ["files not an object", { algorithm: "sha256", files: ["constitution.md"] }],
    ["path traversal entry", { algorithm: "sha256", files: { "../outside.ts": "a".repeat(64) } }],
    ["absolute path entry", { algorithm: "sha256", files: { "/etc/passwd": "a".repeat(64) } }],
    ["non-string digest", { algorithm: "sha256", files: { "constitution.md": 12345 } }],
    ["manifest is an array", ["nope"]],
    ["manifest is null", null],
  ];

  for (const [label, content] of cases) {
    it(`refuses: ${label}`, () => {
      const root = makeTmpRoot();
      try {
        const manifestPath = writeManifest(root, content);
        const result = verifyKernel(root, manifestPath);
        expect(result.verdict.status).toBe("refuse");
        expect(result.degraded).toBe(true);
        expect(result.mustRefuse).toBe(true);
      } finally {
        fs.rmSync(root, { recursive: true, force: true });
      }
    });
  }

  it("refuses when the manifest file is missing entirely", () => {
    const root = makeTmpRoot();
    try {
      const result = verifyKernel(root, path.join(root, "kernel-manifest.json"));
      expect(result.verdict.status).toBe("refuse");
      expect(result.mustRefuse).toBe(true);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

// ─── 6. Policy enforcement while degraded ────────────────────────────

describe("kernel integrity — degraded-mode policy enforcement", () => {
  const ENGINE = new PolicyEngine({} as Database.Database, createDefaultRules());

  it("the kernel rule is part of the default rule set", () => {
    const rules = createDefaultRules();
    expect(rules.some((rule) => rule.id === "kernel.integrity_gate")).toBe(true);
  });

  it("denies financial tools while degraded", () => {
    setKernelDegraded(true);
    for (const toolName of ["transfer_credits", "fund_child", "topup_credits", "x402_fetch"]) {
      const decision = ENGINE.evaluate(makeRequest(toolName));
      expect(decision.action, toolName).toBe("deny");
      expect(decision.reasonCode).toBe("KERNEL_INTEGRITY_DEGRADED");
    }
  });

  it("denies spawn tools while degraded", () => {
    setKernelDegraded(true);
    for (const toolName of ["spawn_child", "delete_sandbox"]) {
      const decision = ENGINE.evaluate(makeRequest(toolName));
      expect(decision.action, toolName).toBe("deny");
    }
  });

  it("denies self-modification tools while degraded", () => {
    setKernelDegraded(true);
    for (const toolName of [
      "edit_own_file",
      "write_file",
      "install_mcp_server",
      "install_npm_package",
      "pull_upstream",
      "reset_to_upstream",
      "revert_last_edit",
    ]) {
      const decision = ENGINE.evaluate(makeRequest(toolName));
      expect(decision.action, toolName).toBe("deny");
    }
  });

  it("denies regardless of input source (deterministic, outside model reasoning)", () => {
    setKernelDegraded(true);
    const rule = createKernelIntegrityRule();
    for (const inputSource of ["agent", "creator", "heartbeat", "wakeup", "system", undefined] as const) {
      const request = makeRequest("transfer_credits");
      request.turnContext.inputSource = inputSource;
      expect(rule.evaluate(request)?.action, String(inputSource)).toBe("deny");
    }
  });

  it("re-allows kernel-gated tools once integrity is verified (not degraded)", () => {
    setKernelDegraded(false);
    const rule = createKernelIntegrityRule();
    expect(rule.evaluate(makeRequest("transfer_credits"))).toBeNull();
    expect(rule.evaluate(makeRequest("spawn_child"))).toBeNull();
    expect(rule.evaluate(makeRequest("edit_own_file"))).toBeNull();
  });

  it("kernel rule outranks domain rules (lowest priority number)", () => {
    const rules = createDefaultRules();
    const kernel = rules.find((rule) => rule.id === "kernel.integrity_gate")!;
    const others = rules.filter((rule) => rule.id !== "kernel.integrity_gate");
    expect(others.every((rule) => rule.priority > kernel.priority)).toBe(true);
  });
});

// ─── 7. Escalation records ───────────────────────────────────────────

describe("kernel integrity — escalation records", () => {
  function makeKV(): { setKV: (k: string, v: string) => void; getKV: (k: string) => string | undefined; store: Map<string, string> } {
    const store = new Map<string, string>();
    return {
      store,
      setKV: (key, value) => void store.set(key, value),
      getKV: (key) => store.get(key),
    };
  }

  it("persists and reads back an escalation record", () => {
    const kv = makeKV();
    const record = recordKernelEscalation(kv.setKV, kv.getKV, {
      verdict: "degraded",
      reason: "kernel files mismatched: [constitution.md] missing: []",
      mismatches: ["constitution.md"],
      missing: [],
    });
    expect(kv.store.get(KERNEL_ESCALATION_KEY)).toBeDefined();
    const read = readKernelEscalation(kv.getKV);
    expect(read?.verdict).toBe("degraded");
    expect(read?.mismatches).toEqual(["constitution.md"]);
    expect(read?.at).toBe(record.at);
  });

  it("deduplicates identical escalations (no audit spam)", () => {
    const kv = makeKV();
    const payload = {
      verdict: "degraded" as const,
      reason: "kernel files mismatched: [constitution.md] missing: []",
      mismatches: ["constitution.md"],
      missing: [],
    };
    const first = recordKernelEscalation(kv.setKV, kv.getKV, payload);
    const second = recordKernelEscalation(kv.setKV, kv.getKV, payload);
    expect(second.at).toBe(first.at);
  });

  it("overwrites when the failure changes", () => {
    const kv = makeKV();
    recordKernelEscalation(kv.setKV, kv.getKV, {
      verdict: "degraded",
      reason: "kernel files mismatched: [constitution.md] missing: []",
      mismatches: ["constitution.md"],
      missing: [],
    });
    recordKernelEscalation(kv.setKV, kv.getKV, {
      verdict: "refuse",
      reason: "kernel manifest unusable",
      mismatches: [],
      missing: [],
    });
    expect(readKernelEscalation(kv.getKV)?.verdict).toBe("refuse");
  });

  it("readKernelEscalation returns null for corrupt or absent records", () => {
    const kv = makeKV();
    expect(readKernelEscalation(kv.getKV)).toBeNull();
    kv.store.set(KERNEL_ESCALATION_KEY, "{not json");
    expect(readKernelEscalation(kv.getKV)).toBeNull();
    kv.store.set(KERNEL_ESCALATION_KEY, "just a string");
    expect(readKernelEscalation(kv.getKV)).toBeNull();
  });
});

// ─── 8. No runtime self-update of the manifest ───────────────────────

describe("kernel integrity — no self-updating at runtime", () => {
  it("verification never writes the manifest or kernel files", () => {
    const root = makeTmpRoot();
    try {
      copyKernelTree(root);
      const manifestPath = path.join(root, "kernel-manifest.json");
      const before = fs.statSync(manifestPath);

      // Spy on every write-capable fs API the kernel module imports.
      const writeSpy = vi.spyOn(fs, "writeFileSync");
      const appendSpy = vi.spyOn(fs, "appendFileSync");
      const rmSpy = vi.spyOn(fs, "rmSync");
      const mkdirSpy = vi.spyOn(fs, "mkdirSync");

      verifyKernel(root, manifestPath);

      expect(writeSpy).not.toHaveBeenCalled();
      expect(appendSpy).not.toHaveBeenCalled();
      expect(rmSpy).not.toHaveBeenCalled();
      expect(mkdirSpy).not.toHaveBeenCalled();

      const after = fs.statSync(manifestPath);
      expect(after.mtimeMs).toBe(before.mtimeMs);

      writeSpy.mockRestore();
      appendSpy.mockRestore();
      rmSpy.mockRestore();
      mkdirSpy.mockRestore();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("generation fails closed if a kernel file is missing (never silently skips)", () => {
    const root = makeTmpRoot();
    try {
      copyKernelTree(root);
      fs.rmSync(path.join(root, "src", "governance", "kernel.ts"));
      expect(() => generateManifest(root)).toThrow(/missing/i);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

// ─── 9. CI/CLI enforcement parity ────────────────────────────────────

describe("kernel integrity — repository-level invariants", () => {
  it("every KERNEL_FILES entry exists in the repo (manifest targets are real)", () => {
    for (const rel of KERNEL_FILES) {
      expect(fs.existsSync(path.join(REPO_ROOT, rel)), rel).toBe(true);
    }
  });

  it("the CI workflow runs the kernel-manifest gate", () => {
    const workflow = fs.readFileSync(
      path.join(REPO_ROOT, ".github", "workflows", "ci.yml"),
      "utf8",
    );
    expect(workflow).toContain("kernel-manifest:");
    expect(workflow).toContain("node scripts/check-kernel-manifest.mjs");
  });

  it("package.json exposes the check:kernel-manifest gate", () => {
    const pkg = JSON.parse(
      fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf8"),
    ) as { scripts: Record<string, string> };
    expect(pkg.scripts["check:kernel-manifest"]).toBe("node scripts/check-kernel-manifest.mjs");
  });

  it("the checker script is dependency-free (no require/import of packages)", () => {
    const script = fs.readFileSync(
      path.join(REPO_ROOT, "scripts", "check-kernel-manifest.mjs"),
      "utf8",
    );
    expect(script).not.toMatch(/\brequire\(/);
    expect(script).not.toMatch(/from\s+"(?!node:)[^"]+"/);
  });
});

import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig(({ mode }) => ({
  // B4.1 (F4.2): CLI tests exercise the policy-guarded relay transport
  // against the real policy module source (workspace specifier -> src).
  resolve: {
    alias: [
      {
        find: "@conway/automaton/net/policy.js",
        replacement: fileURLToPath(new URL("./src/net/policy.ts", import.meta.url)),
      },
      {
        find: "@conway/automaton/config.js",
        replacement: fileURLToPath(new URL("./src/config.ts", import.meta.url)),
      },
    ],
  },
  test: {
    testTimeout: 30_000,
    teardownTimeout: 5_000,
    include: [
      "src/__tests__/**/*.test.ts",
      "packages/cli/src/__tests__/**/*.test.ts",
    ],
    // M1-B5 (F7.1): fix the post-suite vitest hang properly instead of
    // masking it in CI with `timeout ... exit 0`.
    //
    // `pool: "forks"` is the configuration the hardening preflight validated
    // as crash-minimal on this codebase; singleFork keeps runs deterministic
    // in CI. `bail: 1` in CI stops at the first real failure. A CI run that
    // exceeds its job-level `timeout-minutes` now FAILS the job (no bypass),
    // and the Windows worker teardown abort remains a known environment
    // issue tracked via baseline comparison, not papered over.
    ...(mode === "ci" ? { pool: "forks" as const } : {}),
    poolOptions: {
      forks: {
        singleFork: true,
      },
    },
    bail: mode === "ci" ? 1 : 0,
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: [
        "src/__tests__/**",
        "src/types.ts",
        "node_modules/**",
      ],
      thresholds: {
        statements: 60,
        branches: 50,
        functions: 55,
        lines: 60,
      },
      reporter: ["text", "text-summary", "json-summary"],
    },
  },
}));

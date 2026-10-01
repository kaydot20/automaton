#!/usr/bin/env node
/**
 * M1-B5 (F7.3) — Fail-closed source-hygiene gate.
 *
 * Bans raw fetch() and execSync() outside the sanctioned allowlist:
 * - every outbound HTTP request must ride ResilientHttpClient
 *   (src/conway/http-client.ts) so the outbound-network policy applies;
 * - shell-outs must use the audited Conway client fallback
 *   (src/conway/client.ts).
 *
 * Exit 1 (CI fails) on ANY violation. Allowlist changes are deliberate,
 * reviewed edits to this file — exactly the "explicit, reviewed" model the
 * hardening contract requires.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, sep } from "node:path";

const ROOT = process.cwd();
const SCAN_DIRS = [join(ROOT, "src"), join(ROOT, "packages", "cli", "src")];

/**
 * Allowlisted files (repo-relative, forward slashes). Each entry needs a
 * one-line justification; removing a file from this list will fail CI if
 * it still contains a banned call.
 */
const ALLOWLIST = new Map([
  // The sanctioned outbound HTTP client — the only object allowed to call
  // fetch(); every request passes the outbound-network policy per hop.
  ["src/conway/http-client.ts", "sanctioned network client (F4.3)"],
  // Loopback-scoped Ollama discovery (M1-A F4.2: classified low risk).
  ["src/ollama/discover.ts", "loopback-only Ollama discovery"],
  // B4.1: the ONLY raw fetch() in the CLI — the guarded relay transport.
  // Every hop is validated through src/net/policy.ts (purpose "relay",
  // mandatory DNS tier); send.ts/fund.ts are no longer allowlisted.
  ["packages/cli/src/lib/relay-fetch.ts", "CLI guarded relay transport (policy-gated per hop)"],
  // Conway client local-exec fallback (audited path; no sandbox available).
  ["src/conway/client.ts", "Conway client exec fallback"],
]);

// JS-native character classes ONLY (POSIX [[:alnum:]] is not supported in
// JavaScript regex).
// - fetch(: ban unless preceded by a word char or a dot (property access
//   like `resp.fetch(`), so `await fetch(` / `= fetch(` are caught while
//   `prefetch(` / `x.fetch(` are not.
// - execSync(: catch bare AND property access (`process.execSync(`,
//   `child_process.execSync(`) — \b matches after a dot. `fooexecSync(`
//   (single identifier) does not match.
const FETCH_RE = /(^|[^.\w$])fetch\(/;
const EXECSYNC_RE = /\bexecSync\(/;

function walk(dir, out = []) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name === "dist") continue;
      walk(full, out);
    } else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) {
      out.push(full);
    }
  }
  return out;
}

const violations = [];

for (const dir of SCAN_DIRS) {
  for (const file of walk(dir)) {
    const rel = file.slice(ROOT.length + 1).split(sep).join("/");
    if (ALLOWLIST.has(rel)) continue;
    const text = readFileSync(file, "utf8");
    const lines = text.split(/\r?\n/);
    lines.forEach((line, i) => {
      if (FETCH_RE.test(line)) {
        violations.push(`${rel}:${i + 1}: raw fetch() — route through ResilientHttpClient (src/conway/http-client.ts)`);
      }
      if (EXECSYNC_RE.test(line)) {
        violations.push(`${rel}:${i + 1}: execSync() — use the audited Conway client fallback (src/conway/client.ts)`);
      }
    });
  }
}

if (violations.length > 0) {
  console.error("SOURCE HYGIENE VIOLATIONS:");
  for (const v of violations) console.error("  " + v);
  console.error(
    "\nOutbound requests must ride ResilientHttpClient (outbound-network policy, F4.3).",
  );
  console.error(
    "Shell-outs must use the audited Conway client fallback. Allowlist changes are reviewed edits to scripts/check-source-hygiene.mjs.",
  );
  process.exit(1);
}

console.log(
  `source hygiene OK: no unsanctioned raw fetch()/execSync() (${ALLOWLIST.size} allowlisted files)`,
);

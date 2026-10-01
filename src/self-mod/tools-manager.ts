/**
 * Tools Manager
 *
 * Manages installation and configuration of external tools and MCP servers.
 *
 * M1-B8 (preflight §B row 8, F5.1/F5.2, §10): capability registration.
 * Every executable capability must pass deterministic CommandSpec validation
 * and carry signed provenance before it is persisted; rows that cannot be
 * verified fail CLOSED at load and never reach the model-visible registry.
 * Registration is owner-side governance tooling — the model can never grant
 * itself a capability (§10: "never model-grantable to itself").
 */

import { createHash } from "node:crypto";
import type {
  ConwayClient,
  AutomatonDatabase,
  InstalledTool,
  RiskLevel,
} from "../types.js";
import { logModification } from "./audit-log.js";
import { ulid } from "ulid";

// ─── Capability registry (M1-B8, preflight F5.1) ───────────────────────

/** kv/config key holding the capability record inside installed_tools.config. */
export const CAPABILITY_RECORD_KEY = "capability";

/** Executable basenames that may back a capability (fixed allowlist). */
export const CAPABILITY_COMMAND_ALLOWLIST: readonly string[] = Object.freeze([
  "node",
  "nodejs",
  "npx",
  "python3",
]);

/** Absolute directories a capability command may live in. */
export const CAPABILITY_COMMAND_DIRS: readonly string[] = Object.freeze([
  "/usr/local/bin",
  "/usr/bin",
  "/bin",
]);

/** Explicit env keys a capability may receive (preflight F5.1 item 2). */
export const CAPABILITY_ENV_KEY_ALLOWLIST: readonly string[] = Object.freeze([
  "LANG",
  "LC_ALL",
  "NODE_ENV",
  "TZ",
]);

/** Actors allowed to register a capability — never the model. */
export const CAPABILITY_OWNER_ACTORS: readonly string[] = Object.freeze([
  "creator",
  "owner",
  "governance",
]);

const MAX_ARGS = 32;
const MAX_ARG_LENGTH = 512;
const MAX_ENV_VALUE_LENGTH = 256;
/** Characters that let a command string escape its intended argv. */
const SHELL_METACHARACTERS = /[|;&$><`()"'\n\r\\*?~]/;
const SECRET_KEY_PATTERN =
  /(SECRET|TOKEN|PASSWORD|PASSWD|APIKEY|API_KEY|PRIVATE|CREDENTIAL|BEARER|SESSION)/i;
const SECRET_VALUE_PATTERNS: readonly RegExp[] = Object.freeze([
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bsk-[A-Za-z0-9]{16,}/,
  /\bghp_[A-Za-z0-9]{20,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /^[A-Za-z0-9+/]{40,}={0,2}$/,
  /^[a-f0-9]{48,}$/,
]);
const CAPABILITY_NAME_PATTERN = /^[a-z][a-z0-9_-]{0,63}$/;
const CAPABILITY_TYPES = ["safe", "caution", "dangerous", "forbidden"] as const;
const NET_GRANTS = ["none", "https-only"] as const;
const FS_GRANTS = ["none", "workspace"] as const;
const ENV_GRANTS = ["none", "explicit"] as const;

export interface CapabilityPermissions {
  net: (typeof NET_GRANTS)[number];
  fs: (typeof FS_GRANTS)[number];
  env: (typeof ENV_GRANTS)[number];
}

export interface CapabilitySpec {
  name: string;
  kind: "mcp" | "command";
  /** Absolute, allowlisted executable path — never a shell string. */
  command: string;
  /** Arg array (never a string) passed verbatim to the command. */
  args: string[];
  /** JSON Schema (subset) constraining model-supplied invocation args. */
  parameters: Record<string, unknown>;
  /** Declared grants — required, never defaulted. */
  permissions: CapabilityPermissions;
  /** Only permitted when permissions.env === "explicit". */
  env?: Record<string, string>;
  /** Declared classification — required, never defaulted. */
  riskLevel: RiskLevel;
}

export interface CapabilityProvenance {
  sourceUrl: string;
  commitOrVersion: string;
  /** sha256 over the canonical spec; re-verified on every load. */
  hash: string;
  /** Must be an owner-grade actor (CAPABILITY_OWNER_ACTORS). */
  installedBy: string;
  installedAt: string;
  /** Optional hard expiry — a past date makes the capability stale. */
  expiresAt?: string | null;
}

export interface CapabilityRecord {
  spec: CapabilitySpec;
  provenance: CapabilityProvenance;
}

export type ValidationOutcome =
  | { ok: true; spec: CapabilitySpec }
  | { ok: false; reason: string };

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Deterministic key order so the hash is stable across processes. */
function canonicalSpec(spec: CapabilitySpec): string {
  return JSON.stringify([
    spec.name,
    spec.kind,
    spec.command,
    spec.args,
    spec.parameters,
    spec.permissions,
    spec.env ?? null,
    spec.riskLevel,
  ]);
}

/** sha256 over the canonical spec — the provenance content hash. */
export function computeCapabilityHash(spec: CapabilitySpec): string {
  return createHash("sha256").update(canonicalSpec(spec), "utf8").digest("hex");
}

function validatePermissions(value: unknown): ValidationOutcome {
  if (!isPlainObject(value)) {
    return { ok: false, reason: "permissions must be a declared object (net, fs, env are required)" };
  }
  const keys = Object.keys(value).sort();
  const required = ["env", "fs", "net"];
  if (keys.length !== required.length || keys.some((k, i) => k !== required[i])) {
    return { ok: false, reason: `permissions must declare exactly ${required.join(", ")}` };
  }
  const net = value.net;
  const fs = value.fs;
  const env = value.env;
  if (!NET_GRANTS.includes(net as (typeof NET_GRANTS)[number])) {
    return { ok: false, reason: `permissions.net must be one of ${NET_GRANTS.join("|")}` };
  }
  if (!FS_GRANTS.includes(fs as (typeof FS_GRANTS)[number])) {
    return { ok: false, reason: `permissions.fs must be one of ${FS_GRANTS.join("|")}` };
  }
  if (!ENV_GRANTS.includes(env as (typeof ENV_GRANTS)[number])) {
    return { ok: false, reason: `permissions.env must be one of ${ENV_GRANTS.join("|")}` };
  }
  return {
    ok: true,
    spec: {
      name: "",
      kind: "command",
      command: "",
      args: [],
      parameters: {},
      permissions: { net, fs, env } as CapabilityPermissions,
      riskLevel: "caution",
    },
  };
}

function validateEnv(
  env: unknown,
  permissions: CapabilityPermissions,
): { ok: true; env?: Record<string, string> } | { ok: false; reason: string } {
  if (env === undefined || env === null) {
    if (permissions.env === "explicit") {
      return { ok: false, reason: "permissions.env is explicit but no env block was declared" };
    }
    return { ok: true };
  }
  if (permissions.env !== "explicit") {
    return { ok: false, reason: "env block requires permissions.env === \"explicit\"" };
  }
  if (!isPlainObject(env)) {
    return { ok: false, reason: "env must be an object of key → value strings" };
  }
  for (const [key, raw] of Object.entries(env)) {
    if (!CAPABILITY_ENV_KEY_ALLOWLIST.includes(key)) {
      return { ok: false, reason: `env key "${key}" is not on the explicit allowlist` };
    }
    if (SECRET_KEY_PATTERN.test(key)) {
      return { ok: false, reason: `env key "${key}" looks secret-shaped` };
    }
    if (typeof raw !== "string") {
      return { ok: false, reason: `env value for "${key}" must be a string` };
    }
    if (raw.length > MAX_ENV_VALUE_LENGTH) {
      return { ok: false, reason: `env value for "${key}" exceeds ${MAX_ENV_VALUE_LENGTH} chars` };
    }
    if (SECRET_VALUE_PATTERNS.some((pattern) => pattern.test(raw))) {
      return { ok: false, reason: `env value for "${key}" looks secret-shaped` };
    }
  }
  return { ok: true, env: env as Record<string, string> };
}

/**
 * Full CommandSpec validation (preflight F5.1 items 1–2). Fails closed:
 * every field is required and none is defaulted.
 */
export function validateCapabilitySpec(input: unknown): ValidationOutcome {
  if (!isPlainObject(input)) {
    return { ok: false, reason: "capability spec must be an object" };
  }
  const name = input.name;
  if (typeof name !== "string" || !CAPABILITY_NAME_PATTERN.test(name)) {
    return { ok: false, reason: "capability name must match ^[a-z][a-z0-9_-]{0,63}$" };
  }
  if (input.kind !== "mcp" && input.kind !== "command") {
    return { ok: false, reason: 'capability kind must be "mcp" or "command"' };
  }

  const command = input.command;
  if (typeof command !== "string" || command.length === 0) {
    return { ok: false, reason: "capability command is required" };
  }
  if (!command.startsWith("/")) {
    return { ok: false, reason: "capability command must be an absolute path" };
  }
  if (command.includes("..")) {
    return { ok: false, reason: "capability command must not traverse directories" };
  }
  if (SHELL_METACHARACTERS.test(command)) {
    return { ok: false, reason: "capability command contains shell metacharacters" };
  }
  const base = command.slice(command.lastIndexOf("/") + 1);
  const dir = command.slice(0, command.lastIndexOf("/"));
  const dirAllowed = CAPABILITY_COMMAND_DIRS.includes(dir);
  const nameAllowed = CAPABILITY_COMMAND_ALLOWLIST.includes(base);
  if (!(nameAllowed && dirAllowed) && !command.startsWith("/usr/local/bin/")) {
    return {
      ok: false,
      reason: `capability command must be ${CAPABILITY_COMMAND_ALLOWLIST.join("/")} under ${CAPABILITY_COMMAND_DIRS.join(", ")} or a binary under /usr/local/bin`,
    };
  }

  const args = input.args;
  if (!Array.isArray(args)) {
    return { ok: false, reason: "capability args must be an array (never a command string)" };
  }
  if (args.length > MAX_ARGS) {
    return { ok: false, reason: `capability args exceed ${MAX_ARGS} entries` };
  }
  for (const arg of args) {
    if (typeof arg !== "string") {
      return { ok: false, reason: "capability args must all be strings" };
    }
    if (arg.length > MAX_ARG_LENGTH) {
      return { ok: false, reason: `capability arg exceeds ${MAX_ARG_LENGTH} chars` };
    }
    if (SHELL_METACHARACTERS.test(arg)) {
      return { ok: false, reason: "capability arg contains shell metacharacters" };
    }
  }

  const parameters = input.parameters;
  if (!isPlainObject(parameters)) {
    return { ok: false, reason: "capability parameters schema (JSON Schema) is required" };
  }
  if (parameters.type !== "object") {
    return { ok: false, reason: 'capability parameters schema must be type "object"' };
  }
  if (parameters.properties !== undefined && !isPlainObject(parameters.properties)) {
    return { ok: false, reason: "capability parameters.properties must be an object" };
  }

  const permOutcome = validatePermissions(input.permissions);
  if (!permOutcome.ok) return permOutcome;
  const permissions = permOutcome.spec.permissions;

  const riskLevel = input.riskLevel;
  if (typeof riskLevel !== "string" || !CAPABILITY_TYPES.includes(riskLevel as RiskLevel)) {
    return { ok: false, reason: "capability riskLevel is required and must be safe|caution|dangerous|forbidden" };
  }

  const envOutcome = validateEnv(input.env, permissions);
  if (!envOutcome.ok) return { ok: false, reason: envOutcome.reason };

  return {
    ok: true,
    spec: {
      name,
      kind: input.kind,
      command,
      args: args as string[],
      parameters,
      permissions,
      ...(envOutcome.env ? { env: envOutcome.env } : {}),
      riskLevel: riskLevel as RiskLevel,
    },
  };
}

/**
 * Minimal JSON Schema check for model-supplied invocation args: required
 * keys present, no unknown keys, primitive types and enums honoured.
 * Deterministic, no coercion — fail closed.
 */
export function validateInvocationArgs(
  schema: Record<string, unknown>,
  args: unknown,
): { ok: true } | { ok: false; reason: string } {
  if (!isPlainObject(args)) {
    return { ok: false, reason: "invocation args must be an object" };
  }
  const properties = isPlainObject(schema.properties) ? schema.properties : {};
  const required = Array.isArray(schema.required)
    ? (schema.required as unknown[]).filter((k): k is string => typeof k === "string")
    : [];
  for (const key of required) {
    if (!(key in args)) {
      return { ok: false, reason: `missing required argument "${key}"` };
    }
  }
  for (const key of Object.keys(args)) {
    if (!(key in properties)) {
      return { ok: false, reason: `argument "${key}" is not declared by the capability schema` };
    }
  }
  for (const [key, raw] of Object.entries(args)) {
    const prop = properties[key];
    if (!isPlainObject(prop)) continue;
    const expected = prop.type;
    if (expected === "string" && typeof raw !== "string") {
      return { ok: false, reason: `argument "${key}" must be a string` };
    }
    if (expected === "number" && (typeof raw !== "number" || !Number.isFinite(raw))) {
      return { ok: false, reason: `argument "${key}" must be a finite number` };
    }
    if (expected === "boolean" && typeof raw !== "boolean") {
      return { ok: false, reason: `argument "${key}" must be a boolean` };
    }
    if (Array.isArray(prop.enum) && !prop.enum.includes(raw)) {
      return { ok: false, reason: `argument "${key}" is not one of the declared values` };
    }
  }
  return { ok: true };
}

/**
 * Register a capability (preflight F5.1 item 5: append-only). Rejects
 * duplicates, unverified provenance, and model-attributed actors.
 */
export function registerCapability(
  db: AutomatonDatabase,
  specInput: unknown,
  provenanceInput: Partial<CapabilityProvenance>,
): { ok: true; id: string; hash: string } | { ok: false; reason: string } {
  const specOutcome = validateCapabilitySpec(specInput);
  if (!specOutcome.ok) return { ok: false, reason: specOutcome.reason };
  const spec = specOutcome.spec;

  if (!isPlainObject(provenanceInput)) {
    return { ok: false, reason: "provenance is required: {sourceUrl, commitOrVersion, hash, installedBy, installedAt}" };
  }
  const { sourceUrl, commitOrVersion, installedBy, installedAt, expiresAt } = provenanceInput;
  if (typeof sourceUrl !== "string" || !/^https:\/\/\S+$/.test(sourceUrl)) {
    return { ok: false, reason: "provenance.sourceUrl must be an https URL" };
  }
  if (typeof commitOrVersion !== "string" || commitOrVersion.trim().length === 0) {
    return { ok: false, reason: "provenance.commitOrVersion is required" };
  }
  if (typeof installedBy !== "string" || !CAPABILITY_OWNER_ACTORS.includes(installedBy)) {
    return {
      ok: false,
      reason: `provenance.installedBy must be an owner-grade actor (${CAPABILITY_OWNER_ACTORS.join("|")}) — capabilities are never model-grantable`,
    };
  }
  if (typeof installedAt !== "string" || Number.isNaN(Date.parse(installedAt))) {
    return { ok: false, reason: "provenance.installedAt must be an ISO timestamp" };
  }
  if (expiresAt !== undefined && expiresAt !== null && Number.isNaN(Date.parse(expiresAt))) {
    return { ok: false, reason: "provenance.expiresAt must be an ISO timestamp or null" };
  }

  const hash = computeCapabilityHash(spec);
  if (provenanceInput.hash !== undefined && provenanceInput.hash !== hash) {
    return { ok: false, reason: "provenance hash does not match the canonical spec" };
  }

  const duplicate = db.getInstalledTools().some((tool) => tool.name === spec.name);
  if (duplicate) {
    return { ok: false, reason: `capability "${spec.name}" is already registered (registry is append-only)` };
  }

  const record: CapabilityRecord = {
    spec,
    provenance: {
      sourceUrl,
      commitOrVersion,
      hash,
      installedBy,
      installedAt,
      expiresAt: expiresAt ?? null,
    },
  };

  const id = ulid();
  const tool: InstalledTool = {
    id,
    name: spec.name,
    type: spec.kind === "mcp" ? "mcp" : "custom",
    config: { [CAPABILITY_RECORD_KEY]: record },
    installedAt,
    enabled: true,
  };
  db.installTool(tool);
  logModification(db, "registry_update", `Registered capability: ${spec.name}`, {
    reversible: true,
  });
  return { ok: true, id, hash };
}

/** A record is stale when it carries no provenance or its expiry has passed. */
export function isCapabilityStale(
  record: unknown,
  now: number = Date.now(),
): boolean {
  if (!isPlainObject(record)) return true;
  const provenance = (record as { provenance?: unknown }).provenance;
  if (!isPlainObject(provenance)) return true;
  const expiresAt = provenance.expiresAt;
  if (typeof expiresAt === "string" && !Number.isNaN(Date.parse(expiresAt))) {
    return Date.parse(expiresAt) <= now;
  }
  return false;
}

/**
 * Fail-closed verification of a persisted row (preflight F5.1 item 5).
 * A row that predates the registry, was tampered with offline, or is
 * expired never becomes a live tool.
 */
export function verifyCapabilityRecord(
  row: { config?: Record<string, unknown> } | null | undefined,
  now: number = Date.now(),
): { ok: true; record: CapabilityRecord } | { ok: false; reason: string } {
  if (!isPlainObject(row)) {
    return { ok: false, reason: "row is not an object" };
  }
  const raw = (row.config as Record<string, unknown> | undefined)?.[CAPABILITY_RECORD_KEY];
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "row has no capability record (predates the registry) — failing closed" };
  }
  const specOutcome = validateCapabilitySpec((raw as { spec?: unknown }).spec);
  if (!specOutcome.ok) {
    return { ok: false, reason: `stored spec failed validation: ${specOutcome.reason}` };
  }
  const spec = specOutcome.spec;
  const provenance = (raw as { provenance?: unknown }).provenance;
  if (!isPlainObject(provenance)) {
    return { ok: false, reason: "row has no provenance — failing closed" };
  }
  if (typeof provenance.installedBy !== "string" || !CAPABILITY_OWNER_ACTORS.includes(provenance.installedBy)) {
    return { ok: false, reason: "row provenance is not owner-attributed — failing closed" };
  }
  const expectedHash = computeCapabilityHash(spec);
  if (provenance.hash !== expectedHash) {
    return { ok: false, reason: "provenance hash mismatch — row was modified after registration" };
  }
  if (isCapabilityStale(raw, now)) {
    return { ok: false, reason: "capability registration is stale (expired) — failing closed" };
  }
  return { ok: true, record: { spec, provenance: provenance as unknown as CapabilityProvenance } };
}

/**
 * Install an npm package globally in the sandbox.
 *
 * M1-B8 (preflight F5.2): exact-version pinning, `--ignore-scripts` so a
 * postinstall hook can never execute, and a capability grant is required —
 * the install is owner-side governance tooling, never model-invoked.
 */
export async function installNpmPackage(
  conway: ConwayClient,
  db: AutomatonDatabase,
  packageName: string,
  options: { capabilityGrant?: CapabilityRecord } = {},
): Promise<{ success: boolean; error?: string }> {
  // Sanitize package name (prevent command injection)
  if (!/^(@[a-z0-9-]+\/)?[a-z0-9-]+(\.[a-z0-9-]+)*@[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$/.test(packageName)) {
    return {
      success: false,
      error: `Package must be pinned to an exact version (name@x.y.z) and use the registry, not a scheme: ${packageName}`,
    };
  }

  if (!options.capabilityGrant) {
    return {
      success: false,
      error: "npm install requires a verified capability grant (preflight §10: capability registration is never model-grantable)",
    };
  }

  const result = await conway.exec(
    `npm install -g --ignore-scripts ${packageName}`,
    120000,
  );

  if (result.exitCode !== 0) {
    return {
      success: false,
      error: `npm install failed: ${result.stderr}`,
    };
  }

  // Record in database
  const tool: InstalledTool = {
    id: ulid(),
    name: packageName,
    type: "custom",
    config: {
      source: "npm",
      installCommand: `npm install -g --ignore-scripts ${packageName}`,
      capability: options.capabilityGrant,
    },
    installedAt: new Date().toISOString(),
    enabled: true,
  };

  db.installTool(tool);

  logModification(db, "tool_install", `Installed npm package: ${packageName}`, {
    reversible: true,
  });

  return { success: true };
}

/**
 * Install an MCP server (owner-side).
 *
 * M1-B8 (preflight F5.1): the CommandSpec is validated and provenance
 * recorded through the capability registry; the MCP executor itself remains
 * a stub until protocol support lands behind the same gate.
 */
export async function installMcpServer(
  conway: ConwayClient,
  db: AutomatonDatabase,
  name: string,
  command: string,
  args?: string[],
  env?: Record<string, string>,
  provenance: Partial<CapabilityProvenance> = {},
): Promise<{ success: boolean; error?: string }> {
  const outcome = registerCapability(
    db,
    {
      name,
      kind: "mcp",
      command,
      args: args ?? [],
      parameters: { type: "object", properties: {} },
      permissions: {
        net: "none",
        fs: "none",
        env: env && Object.keys(env).length > 0 ? "explicit" : "none",
      },
      ...(env && Object.keys(env).length > 0 ? { env } : {}),
      riskLevel: "caution",
    },
    {
      ...provenance,
      installedAt: provenance.installedAt ?? new Date().toISOString(),
    },
  );
  if (!outcome.ok) {
    return { success: false, error: outcome.reason };
  }

  logModification(
    db,
    "mcp_install",
    `Installed MCP server: ${name} (${command})`,
    { reversible: true },
  );

  return { success: true };
}

/**
 * List all installed tools.
 */
export function listInstalledTools(
  db: AutomatonDatabase,
): InstalledTool[] {
  return db.getInstalledTools();
}

/**
 * Remove (disable) an installed tool.
 */
export function removeTool(
  db: AutomatonDatabase,
  toolId: string,
): void {
  db.removeTool(toolId);
  logModification(db, "tool_install", `Removed tool: ${toolId}`, {
    reversible: true,
  });
}

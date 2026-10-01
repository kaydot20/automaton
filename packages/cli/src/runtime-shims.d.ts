declare module "@conway/automaton/config.js" {
  export interface AutomatonCliConfig {
    name: string;
    walletAddress: string;
    creatorAddress: string;
    sandboxId: string;
    dbPath: string;
    inferenceModel: string;
    conwayApiUrl: string;
    conwayApiKey: string;
    openaiApiKey?: string;
    anthropicApiKey?: string;
    socialRelayUrl?: string;
  }

  export function loadConfig(): AutomatonCliConfig | null;
  export function resolvePath(p: string): string;
}

declare module "@conway/automaton/net/policy.js" {
  export interface DnsResolver {
    lookup(hostname: string): Promise<string[]>;
  }

  export interface OutboundPolicyOptions {
    purpose: "payment" | "fetch" | "relay" | "discovery";
    allowedDomains?: string[];
    allowHttpOnLoopback?: boolean;
    resolver?: DnsResolver;
    requireDnsResolution?: boolean;
  }

  export type NetworkCheckResult =
    | { allowed: true }
    | { allowed: false; code: string; message: string };

  export function assertOutboundAllowed(
    url: string,
    options: OutboundPolicyOptions,
  ): Promise<NetworkCheckResult>;

  export function isHostnameWellFormed(hostname: string): boolean;
}

declare module "@conway/automaton/state/database.js" {
  export interface CliToolCall {
    name: string;
    result: string;
    error?: string;
  }

  export interface CliTurn {
    id: string;
    timestamp: string;
    state: string;
    input?: string;
    inputSource?: string;
    thinking: string;
    toolCalls: CliToolCall[];
    tokenUsage: { totalTokens: number };
    costCents: number;
  }

  export interface CliHeartbeatEntry {
    enabled: boolean;
  }

  export interface CliInstalledTool {
    id: string;
    name: string;
  }

  export interface AutomatonCliDatabase {
    getAgentState(): string;
    getTurnCount(): number;
    getInstalledTools(): CliInstalledTool[];
    getHeartbeatEntries(): CliHeartbeatEntry[];
    getRecentTurns(limit: number): CliTurn[];
    close(): void;
  }

  export function createDatabase(path: string): AutomatonCliDatabase;
}

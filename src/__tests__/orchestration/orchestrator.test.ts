import type BetterSqlite3 from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ulid } from "ulid";
import { Orchestrator } from "../../orchestration/orchestrator.js";
import type { AgentTracker, FundingProtocol } from "../../orchestration/types.js";
import type { MessageTransport } from "../../orchestration/messaging.js";
import { ColonyMessaging } from "../../orchestration/messaging.js";
import type { AutomatonDatabase } from "../../types.js";
import { createInMemoryDb } from "./test-db.js";

// ─── Fixtures ───────────────────────────────────────────────────

const IDENTITY = {
  name: "test",
  address: "0x1234" as any,
  account: {} as any,
  creatorAddress: "0x0000" as any,
  sandboxId: "sb-1",
  apiKey: "key",
  createdAt: "2026-01-01T00:00:00Z",
};

function makeAgentTracker(overrides: Partial<AgentTracker> = {}): AgentTracker {
  return {
    getIdle: vi.fn().mockReturnValue([]),
    getBestForTask: vi.fn().mockReturnValue(null),
    updateStatus: vi.fn(),
    register: vi.fn(),
    ...overrides,
  };
}

function makeFunding(overrides: Partial<FundingProtocol> = {}): FundingProtocol {
  return {
    fundChild: vi.fn().mockResolvedValue({ success: true }),
    recallCredits: vi.fn().mockResolvedValue({ success: true, amountCents: 0 }),
    getBalance: vi.fn().mockResolvedValue(1000),
    ...overrides,
  };
}

function makeInference(chatResult: Record<string, unknown> = {}) {
  return {
    chat: vi.fn().mockResolvedValue({
      content: JSON.stringify({ estimatedSteps: 2, reason: "simple", stepOutline: [], ...chatResult }),
      usage: { inputTokens: 10, outputTokens: 10 },
    }),
  };
}

function makeMessaging(_raw: BetterSqlite3.Database): {
  messaging: ColonyMessaging;
  transport: MessageTransport;
  automataDb: AutomatonDatabase;
} {
  const transport: MessageTransport = {
    deliver: vi.fn().mockResolvedValue(undefined),
    getRecipients: vi.fn().mockReturnValue([]),
  };

  const automataDb = {
    raw: _raw,
    getIdentity: (key: string) => (key === "address" ? "0x1234" : undefined),
    getChildren: () => [],
    getUnprocessedInboxMessages: (_limit: number) => [],
    markInboxMessageProcessed: (_id: string) => {},
  } as unknown as AutomatonDatabase;

  const messaging = new ColonyMessaging(transport, automataDb);
  return { messaging, transport, automataDb };
}

function makeOrchestrator(
  db: BetterSqlite3.Database,
  overrides: {
    agentTracker?: AgentTracker;
    funding?: FundingProtocol;
    inference?: ReturnType<typeof makeInference>;
    config?: any;
    messaging?: ColonyMessaging;
  } = {},
): Orchestrator {
  const { messaging } = makeMessaging(db);
  return new Orchestrator({
    db,
    agentTracker: overrides.agentTracker ?? makeAgentTracker(),
    funding: overrides.funding ?? makeFunding(),
    messaging: overrides.messaging ?? messaging,
    inference: overrides.inference ?? (makeInference() as any),
    identity: IDENTITY,
    config: overrides.config ?? {},
  });
}

function setOrchestratorState(db: BetterSqlite3.Database, state: Record<string, unknown>): void {
  db.prepare(
    "INSERT OR REPLACE INTO kv (key, value, updated_at) VALUES (?, ?, datetime('now'))",
  ).run("orchestrator.state", JSON.stringify(state));
}

function insertGoal(db: BetterSqlite3.Database, overrides: {
  id?: string;
  title?: string;
  description?: string;
  status?: string;
} = {}): string {
  const id = overrides.id ?? ulid();
  db.prepare(
    "INSERT INTO goals (id, title, description, status, created_at) VALUES (?, ?, ?, ?, ?)",
  ).run(
    id,
    overrides.title ?? "Test Goal",
    overrides.description ?? "A test goal",
    overrides.status ?? "active",
    new Date().toISOString(),
  );
  return id;
}

function insertTask(db: BetterSqlite3.Database, overrides: {
  id?: string;
  goalId: string;
  title?: string;
  description?: string;
  status?: string;
  assignedTo?: string | null;
  agentRole?: string;
  priority?: number;
  dependencies?: string[];
}): string {
  const id = overrides.id ?? ulid();
  db.prepare(
    `INSERT INTO task_graph
     (id, goal_id, title, description, status, assigned_to, agent_role, priority, dependencies, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    id,
    overrides.goalId,
    overrides.title ?? "Test Task",
    overrides.description ?? "A test task",
    overrides.status ?? "pending",
    overrides.assignedTo ?? null,
    overrides.agentRole ?? "generalist",
    overrides.priority ?? 50,
    JSON.stringify(overrides.dependencies ?? []),
    new Date().toISOString(),
  );
  return id;
}

function getOrchestratorState(db: BetterSqlite3.Database): Record<string, unknown> | null {
  const row = db.prepare("SELECT value FROM kv WHERE key = 'orchestrator.state'").get() as
    | { value: string }
    | undefined;
  if (!row?.value) return null;
  try {
    return JSON.parse(row.value);
  } catch {
    return null;
  }
}

// ─── Tests ──────────────────────────────────────────────────────

describe("orchestration/Orchestrator", () => {
  let db: BetterSqlite3.Database;

  beforeEach(() => {
    db = createInMemoryDb();
  });

  afterEach(() => {
    db.close();
  });

  // ─── tick() phase transitions ────────────────────────────────

  describe("tick() phase transitions", () => {
    it("idle with no goals stays idle", async () => {
      const orc = makeOrchestrator(db);
      const result = await orc.tick();
      expect(result.phase).toBe("idle");
      expect(result.goalsActive).toBe(0);
    });

    it("idle with active goal transitions to classifying", async () => {
      insertGoal(db, { status: "active" });
      // Force inference to return low step count so classifying resolves cleanly
      const inference = makeInference({ estimatedSteps: 2 });
      const orc = makeOrchestrator(db, { inference: inference as any });
      const result = await orc.tick();
      // After classifying (simple goal) -> executing phase saved; result shows executing
      expect(["classifying", "executing"]).toContain(result.phase);
    });

    it("classifying with simple goal (<=3 steps) transitions to executing", async () => {
      const goalId = insertGoal(db, { title: "Short", description: "Brief" });
      setOrchestratorState(db, { phase: "classifying", goalId, replanCount: 0, failedTaskId: null, failedError: null });
      const inference = makeInference({ estimatedSteps: 2 });
      const orc = makeOrchestrator(db, { inference: inference as any });
      const result = await orc.tick();
      expect(result.phase).toBe("executing");
    });

    it("classifying with complex goal (>3 steps) transitions to planning", async () => {
      const goalId = insertGoal(db, { title: "Complex Goal", description: "Needs multiple coordinated steps" });
      setOrchestratorState(db, { phase: "classifying", goalId, replanCount: 0, failedTaskId: null, failedError: null });

      // classifyComplexity returns high step count → classifying saves "planning" phase
      const inference = makeInference({ estimatedSteps: 5 });

      const orc = makeOrchestrator(db, { inference: inference as any });
      const result = await orc.tick();
      // One tick: classifying detects >3 steps → transitions to planning
      expect(result.phase).toBe("planning");
    });

    it("planning phase calls inference and transitions to plan_review", async () => {
      const goalId = insertGoal(db, { title: "Complex Goal", description: "Needs multiple coordinated steps" });
      setOrchestratorState(db, { phase: "planning", goalId, replanCount: 0, failedTaskId: null, failedError: null });

      // planGoal calls inference.chat once
      const inference = {
        chat: vi.fn().mockResolvedValueOnce({
          content: JSON.stringify({
            analysis: "Analysis text",
            strategy: "Strategy text",
            customRoles: [],
            tasks: [
              {
                title: "Task One",
                description: "Do the first thing",
                agentRole: "generalist",
                dependencies: [],
                estimatedCostCents: 50,
                priority: 50,
                timeoutMs: 60000,
              },
            ],
            risks: [],
            estimatedTotalCostCents: 50,
            estimatedTimeMinutes: 10,
          }),
          usage: {},
        }),
      };

      const orc = makeOrchestrator(db, { inference: inference as any });
      const result = await orc.tick();
      expect(result.phase).toBe("plan_review");
    });

    it("plan_review with plan in KV auto-approves (auto mode) and transitions to executing", async () => {
      const goalId = insertGoal(db);
      insertTask(db, { goalId, title: "task-one", description: "Do something" });
      setOrchestratorState(db, { phase: "plan_review", goalId, replanCount: 0, failedTaskId: null, failedError: null });

      // Store a valid plan in KV under the plan key
      const plan = {
        analysis: "Analysis",
        strategy: "Strategy",
        customRoles: [],
        tasks: [{ title: "Task One", description: "Desc", agentRole: "generalist", dependencies: [], estimatedCostCents: 50, priority: 50, timeoutMs: 60000 }],
        risks: [],
        estimatedTotalCostCents: 50,
        estimatedTimeMinutes: 10,
      };
      db.prepare("INSERT OR REPLACE INTO kv (key, value, updated_at) VALUES (?, ?, datetime('now'))").run(
        `orchestrator.plan.${goalId}`,
        JSON.stringify(plan),
      );

      const orc = makeOrchestrator(db);
      const result = await orc.tick();
      expect(result.phase).toBe("executing");
    });

    it("plan_review with no plan in KV auto-advances to executing", async () => {
      const goalId = insertGoal(db);
      insertTask(db, { goalId, title: "existing-task", description: "Do something" });
      setOrchestratorState(db, { phase: "plan_review", goalId, replanCount: 0, failedTaskId: null, failedError: null });
      // No plan in KV — should skip review and go to executing

      const orc = makeOrchestrator(db);
      const result = await orc.tick();
      expect(result.phase).toBe("executing");
    });

    it("complete phase resets to idle", async () => {
      const goalId = insertGoal(db, { status: "completed" });
      setOrchestratorState(db, { phase: "complete", goalId, replanCount: 0, failedTaskId: null, failedError: null });
      const funding = makeFunding();
      const orc = makeOrchestrator(db, { funding });
      const result = await orc.tick();
      expect(result.phase).toBe("idle");
    });

    it("failed phase resets to idle after logging", async () => {
      const goalId = insertGoal(db, { status: "active" });
      setOrchestratorState(db, {
        phase: "failed",
        goalId,
        replanCount: 3,
        failedTaskId: null,
        failedError: "Something went wrong",
      });
      const orc = makeOrchestrator(db);
      const result = await orc.tick();
      // handleFailedPhase marks the goal as failed and resets to idle
      // so the orchestrator can pick up other active goals.
      expect(result.phase).toBe("idle");
    });
  });

  // ─── matchTaskToAgent ────────────────────────────────────────

  describe("matchTaskToAgent", () => {
    function makeTask(goalId: string, overrides: Partial<{ agentRole: string; id: string }> = {}) {
      return {
        id: overrides.id ?? ulid(),
        parentId: null,
        goalId,
        title: "Task",
        description: "desc",
        status: "pending" as const,
        assignedTo: null,
        agentRole: overrides.agentRole ?? "generalist",
        priority: 50,
        dependencies: [],
        result: null,
        metadata: {
          estimatedCostCents: 10,
          actualCostCents: 0,
          maxRetries: 3,
          retryCount: 0,
          timeoutMs: 60000,
          createdAt: new Date().toISOString(),
          startedAt: null,
          completedAt: null,
        },
      };
    }

    it("returns idle agent with matching role", async () => {
      const goalId = insertGoal(db);
      const agentTracker = makeAgentTracker({
        getIdle: vi.fn().mockReturnValue([
          { address: "0xspecialist", name: "Specialist", role: "researcher", status: "healthy" },
          { address: "0xgeneralist", name: "Generalist", role: "generalist", status: "healthy" },
        ]),
      });
      const orc = makeOrchestrator(db, { agentTracker });
      const result = await orc.matchTaskToAgent(makeTask(goalId, { agentRole: "researcher" }));
      expect(result.agentAddress).toBe("0xspecialist");
      expect(result.spawned).toBe(false);
    });

    it("returns best idle agent when no exact role match", async () => {
      const goalId = insertGoal(db);
      const agentTracker = makeAgentTracker({
        getIdle: vi.fn().mockReturnValue([]),
        getBestForTask: vi.fn().mockReturnValue({ address: "0xbest", name: "Best" }),
      });
      const orc = makeOrchestrator(db, { agentTracker });
      const result = await orc.matchTaskToAgent(makeTask(goalId));
      expect(result.agentAddress).toBe("0xbest");
      expect(result.spawned).toBe(false);
    });

    it("calls spawnAgent from config when no idle agents", async () => {
      const goalId = insertGoal(db);
      const agentTracker = makeAgentTracker({
        getIdle: vi.fn().mockReturnValue([]),
        getBestForTask: vi.fn().mockReturnValue(null),
      });
      const spawnAgent = vi.fn().mockResolvedValue({ address: "0xspawned", name: "Spawned", sandboxId: "sb-2" });
      const orc = makeOrchestrator(db, {
        agentTracker,
        config: { spawnAgent },
      });
      const result = await orc.matchTaskToAgent(makeTask(goalId));
      expect(result.agentAddress).toBe("0xspawned");
      expect(result.spawned).toBe(true);
      expect(spawnAgent).toHaveBeenCalledTimes(1);
      expect(agentTracker.register).toHaveBeenCalled();
    });

    it("falls back to busy agent when spawn is disabled", async () => {
      const goalId = insertGoal(db);
      // Insert a running child into the DB
      db.prepare(
        "INSERT INTO children (id, name, address, sandbox_id, genesis_prompt, creator_message, funded_amount_cents, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ).run(ulid(), "BusyAgent", "0xbusy", "sb-3", "prompt", "msg", 0, "running", new Date().toISOString());

      const agentTracker = makeAgentTracker({
        getIdle: vi.fn().mockReturnValue([]),
        getBestForTask: vi.fn().mockReturnValue(null),
      });
      const orc = makeOrchestrator(db, {
        agentTracker,
        config: { disableSpawn: true },
      });
      const result = await orc.matchTaskToAgent(makeTask(goalId));
      expect(result.agentAddress).toBe("0xbusy");
      expect(result.spawned).toBe(false);
    });

    it("self-assigns to parent when no child agent is available", async () => {
      const goalId = insertGoal(db);
      const agentTracker = makeAgentTracker({
        getIdle: vi.fn().mockReturnValue([]),
        getBestForTask: vi.fn().mockReturnValue(null),
      });
      const orc = makeOrchestrator(db, {
        agentTracker,
        config: { disableSpawn: true },
      });
      // When no child agents are available, matchTaskToAgent falls back to
      // self-assigning the task to the parent identity.
      const result = await orc.matchTaskToAgent(makeTask(goalId));
      expect(result.agentAddress).toBe(IDENTITY.address);
      expect(result.agentName).toBe(IDENTITY.name);
      expect(result.spawned).toBe(false);
    });
  });

  // ─── fundAgentForTask ────────────────────────────────────────

  describe("fundAgentForTask", () => {
    function makeTaskWithCost(goalId: string, estimatedCostCents: number) {
      return {
        id: ulid(),
        parentId: null,
        goalId,
        title: "Task",
        description: "desc",
        status: "pending" as const,
        assignedTo: null,
        agentRole: "generalist",
        priority: 50,
        dependencies: [],
        result: null,
        metadata: {
          estimatedCostCents,
          actualCostCents: 0,
          maxRetries: 3,
          retryCount: 0,
          timeoutMs: 60000,
          createdAt: new Date().toISOString(),
          startedAt: null,
          completedAt: null,
        },
      };
    }

    it("calls funding.fundChild with at least the default amount", async () => {
      const goalId = insertGoal(db);
      const funding = makeFunding();
      const orc = makeOrchestrator(db, { funding, config: { defaultTaskFundingCents: 25 } });
      await orc.fundAgentForTask("0xagent", makeTaskWithCost(goalId, 0));
      expect(funding.fundChild).toHaveBeenCalledWith("0xagent", 25);
    });

    it("skips funding when estimated amount and default are both 0", async () => {
      const goalId = insertGoal(db);
      const funding = makeFunding();
      const orc = makeOrchestrator(db, { funding, config: { defaultTaskFundingCents: 0 } });
      await orc.fundAgentForTask("0xagent", makeTaskWithCost(goalId, 0));
      expect(funding.fundChild).not.toHaveBeenCalled();
    });

    it("throws when fundChild reports failure", async () => {
      const goalId = insertGoal(db);
      const funding = makeFunding({
        fundChild: vi.fn().mockResolvedValue({ success: false }),
      });
      const orc = makeOrchestrator(db, { funding, config: { defaultTaskFundingCents: 25 } });
      await expect(orc.fundAgentForTask("0xagent", makeTaskWithCost(goalId, 25))).rejects.toThrow(
        "Funding transfer failed for 0xagent",
      );
    });
  });

  // ─── collectResults ──────────────────────────────────────────

  describe("collectResults", () => {
    function buildMessagingWithResults(
      raw: BetterSqlite3.Database,
      messages: Array<{ type: string; content: string }>,
    ) {
      const processedMessages = messages.map((msg) => ({
        message: {
          id: ulid(),
          type: msg.type,
          from: "0xagent",
          to: "0x1234",
          goalId: null,
          taskId: null,
          content: msg.content,
          priority: "normal" as const,
          requiresResponse: false,
          expiresAt: null,
          createdAt: new Date().toISOString(),
        },
        handledBy: "handleTaskResult",
        success: true,
      }));

      const messaging = {
        processInbox: vi.fn().mockResolvedValue(processedMessages),
        createMessage: vi.fn().mockReturnValue({}),
        send: vi.fn().mockResolvedValue(undefined),
      } as unknown as ColonyMessaging;

      return messaging;
    }

    it("processes task_result messages from inbox", async () => {
      const goalId = insertGoal(db);
      const taskId = insertTask(db, { goalId });
      const content = JSON.stringify({ taskId, success: true, output: "done", artifacts: [], costCents: 5, duration: 100 });
      const messaging = buildMessagingWithResults(db, [{ type: "task_result", content }]);
      const orc = makeOrchestrator(db, { messaging });
      const results = await orc.collectResults();
      expect(results).toHaveLength(1);
      expect(results[0].success).toBe(true);
      expect(results[0].output).toBe("done");
    });

    it("ignores non-task_result messages", async () => {
      const messaging = buildMessagingWithResults(db, [
        { type: "alert", content: JSON.stringify({ message: "just an alert" }) },
      ]);
      const orc = makeOrchestrator(db, { messaging });
      const results = await orc.collectResults();
      expect(results).toHaveLength(0);
    });

    it("returns empty array when inbox is empty", async () => {
      const messaging = buildMessagingWithResults(db, []);
      const orc = makeOrchestrator(db, { messaging });
      const results = await orc.collectResults();
      expect(results).toHaveLength(0);
    });

    function buildMessagingWithResults(
      _raw: BetterSqlite3.Database,
      messages: Array<{ type: string; content: string }>,
    ) {
      const processedMessages = messages.map((msg) => ({
        message: {
          id: ulid(),
          type: msg.type,
          from: "0xagent",
          to: "0x1234",
          goalId: null,
          taskId: null,
          content: msg.content,
          priority: "normal" as const,
          requiresResponse: false,
          expiresAt: null,
          createdAt: new Date().toISOString(),
        },
        handledBy: "handleTaskResult",
        success: true,
      }));

      return {
        processInbox: vi.fn().mockResolvedValue(processedMessages),
        createMessage: vi.fn().mockReturnValue({}),
        send: vi.fn().mockResolvedValue(undefined),
      } as unknown as ColonyMessaging;
    }
  });

  // ─── handleFailure ───────────────────────────────────────────

  describe("handleFailure", () => {
    function makeTaskNode(goalId: string, taskId: string) {
      return {
        id: taskId,
        parentId: null,
        goalId,
        title: "Failing Task",
        description: "This task fails",
        status: "running" as const,
        assignedTo: "0xagent",
        agentRole: "generalist",
        priority: 50,
        dependencies: [],
        result: null,
        metadata: {
          estimatedCostCents: 10,
          actualCostCents: 0,
          maxRetries: 0,
          retryCount: 0,
          timeoutMs: 60000,
          createdAt: new Date().toISOString(),
          startedAt: null,
          completedAt: null,
        },
      };
    }

    it("transitions to replanning when task permanently fails and replanCount < maxReplans", async () => {
      const goalId = insertGoal(db, { status: "active" });
      // max_retries=0 so failTask marks it permanently failed (no retry budget)
      const taskId = insertTask(db, { goalId, status: "running" });
      db.prepare("UPDATE task_graph SET max_retries = 0, retry_count = 0 WHERE id = ?").run(taskId);
      setOrchestratorState(db, { phase: "executing", goalId, replanCount: 0, failedTaskId: null, failedError: null });

      const orc = makeOrchestrator(db, { config: { maxReplans: 3 } });
      await orc.handleFailure(makeTaskNode(goalId, taskId), "some error");

      const state = getOrchestratorState(db);
      expect(state?.phase).toBe("replanning");
      expect(state?.failedTaskId).toBe(taskId);
      expect(state?.failedError).toBe("some error");
    });

    it("transitions to failed when replanCount >= maxReplans", async () => {
      const goalId = insertGoal(db, { status: "active" });
      // max_retries=0 so failTask marks it permanently failed (no retry budget)
      const taskId = insertTask(db, { goalId, status: "running" });
      db.prepare("UPDATE task_graph SET max_retries = 0, retry_count = 0 WHERE id = ?").run(taskId);
      setOrchestratorState(db, { phase: "executing", goalId, replanCount: 3, failedTaskId: null, failedError: null });

      const orc = makeOrchestrator(db, { config: { maxReplans: 3 } });
      await orc.handleFailure(makeTaskNode(goalId, taskId), "fatal");

      const state = getOrchestratorState(db);
      expect(state?.phase).toBe("failed");
    });

    it("retries task when retry budget allows (maxRetries > retryCount)", async () => {
      const goalId = insertGoal(db, { status: "active" });
      const taskId = insertTask(db, { goalId, status: "running" });
      // Insert with retries available
      db.prepare("UPDATE task_graph SET max_retries = 3, retry_count = 0 WHERE id = ?").run(taskId);
      setOrchestratorState(db, { phase: "executing", goalId, replanCount: 0, failedTaskId: null, failedError: null });

      const orc = makeOrchestrator(db, { config: { maxReplans: 3 } });
      await orc.handleFailure(makeTaskNode(goalId, taskId), "transient");

      // Task should have been retried (status pending or blocked, not necessarily failed)
      const taskRow = db.prepare("SELECT status FROM task_graph WHERE id = ?").get(taskId) as
        | { status: string }
        | undefined;
      expect(["pending", "blocked"]).toContain(taskRow?.status);
    });
  });

  // ─── handlePlanReviewPhase ───────────────────────────────────

  describe("handlePlanReviewPhase (via tick)", () => {
    function storePlan(db: BetterSqlite3.Database, goalId: string, planOverrides: Record<string, unknown> = {}): void {
      const plan = {
        analysis: "Analysis",
        strategy: "Strategy",
        customRoles: [],
        tasks: [
          {
            title: "Task One",
            description: "Do something",
            agentRole: "generalist",
            dependencies: [],
            estimatedCostCents: 100,
            priority: 50,
            timeoutMs: 60000,
          },
        ],
        risks: [],
        estimatedTotalCostCents: 100,
        estimatedTimeMinutes: 5,
        ...planOverrides,
      };
      db.prepare("INSERT OR REPLACE INTO kv (key, value, updated_at) VALUES (?, ?, datetime('now'))").run(
        `orchestrator.plan.${goalId}`,
        JSON.stringify(plan),
      );
    }

    it("approved plan transitions from plan_review to executing", async () => {
      const goalId = insertGoal(db);
      insertTask(db, { goalId, title: "t1", description: "desc" });
      storePlan(db, goalId, { estimatedTotalCostCents: 100 }); // under auto threshold
      setOrchestratorState(db, { phase: "plan_review", goalId, replanCount: 0, failedTaskId: null, failedError: null });

      const orc = makeOrchestrator(db);
      const result = await orc.tick();
      expect(result.phase).toBe("executing");
    });

    it("rejected plan (malformed/no tasks in plan) transitions to executing when KV missing", async () => {
      const goalId = insertGoal(db);
      insertTask(db, { goalId, title: "t1", description: "desc" });
      // No plan in KV — handlePlanReviewPhase returns executing
      setOrchestratorState(db, { phase: "plan_review", goalId, replanCount: 0, failedTaskId: null, failedError: null });

      const orc = makeOrchestrator(db);
      const result = await orc.tick();
      expect(result.phase).toBe("executing");
    });

    it("supervised mode stays in plan_review (awaiting human approval)", async () => {
      const goalId = insertGoal(db);
      insertTask(db, { goalId, title: "t1", description: "desc" });
      storePlan(db, goalId);
      setOrchestratorState(db, { phase: "plan_review", goalId, replanCount: 0, failedTaskId: null, failedError: null });

      // The orchestrator always calls reviewPlan with mode: "auto". To exercise
      // the await-human-approval catch branch we mock the plan-mode module here.
      const reviewPlan = await import("../../orchestration/plan-mode.js");
      const spy = vi.spyOn(reviewPlan, "reviewPlan").mockRejectedValue(new Error("awaiting human approval"));
      try {
        const orc = makeOrchestrator(db);
        const result = await orc.tick();
        expect(result.phase).toBe("plan_review");
      } finally {
        spy.mockRestore();
      }
    });

    it("first budget rejection triggers exactly one bounded cheaper-plan replan", async () => {
      const goalId = insertGoal(db);
      insertTask(db, { goalId, title: "t1", description: "desc" });

      storePlan(db, goalId, { estimatedTotalCostCents: 9000 }); // above ceiling (5000)
      setOrchestratorState(db, { phase: "plan_review", goalId, replanCount: 0, failedTaskId: null, failedError: null });

      const orc = makeOrchestrator(db);
      const result = await orc.tick();

      // Rejection #1 -> exactly one bounded replan attempt (planning phase).
      expect(result.phase).toBe("planning");

      const countRow = db.prepare("SELECT value FROM kv WHERE key = ?").get(`orchestrator.budget_rejections.${goalId}`) as { value: string };
      expect(countRow.value).toBe("1");

      // Goal has NOT been blocked on the first rejection.
      const goalRow = db.prepare("SELECT status FROM goals WHERE id = ?").get(goalId) as { status: string };
      expect(goalRow.status).toBe("active");
    });

    it("second consecutive budget rejection pauses the goal and cannot replan further", async () => {
      const goalId = insertGoal(db);
      insertTask(db, { goalId, title: "t1", description: "desc" });

      // The single bounded cheaper-plan attempt already happened (counter = 1).
      db.prepare("INSERT OR REPLACE INTO kv (key, value, updated_at) VALUES (?, ?, datetime('now'))")
        .run(`orchestrator.budget_rejections.${goalId}`, "1");

      // Another over-budget plan must NOT start a new planning -> review -> planning loop.
      storePlan(db, goalId, { estimatedTotalCostCents: 9000 });
      setOrchestratorState(db, { phase: "plan_review", goalId, replanCount: 0, failedTaskId: null, failedError: null });

      const orc = makeOrchestrator(db);
      const tick1 = await orc.tick();
      expect(tick1.phase).toBe("idle");

      const goalRow = db.prepare("SELECT status FROM goals WHERE id = ?").get(goalId) as { status: string };
      expect(goalRow.status).toBe("paused");

      const taskRow = db.prepare("SELECT status FROM task_graph WHERE goal_id = ? AND title = 't1'").get(goalId) as { status: string };
      expect(taskRow.status).toBe("blocked");

      const escalation = db.prepare("SELECT value FROM kv WHERE key = ?").get(`orchestrator.budget_escalation.${goalId}`) as { value: string };
      const escalationData = JSON.parse(escalation.value);
      expect(escalationData.code).toBe("PLAN_COST_MISMATCH"); // matches the 9000/100 plan fixture used here
      expect(escalationData.action).toBe("goal_paused_tasks_blocked");

      // A later tick stays idle: paused goals are not re-picked, no loop.
      const tick2 = await orc.tick();
      expect(tick2.phase).toBe("idle");
    });

    it("a cheaper replanned plan within the ceiling is approved and executes", async () => {
      const goalId = insertGoal(db);
      insertTask(db, { goalId, title: "t1", description: "desc" });

      storePlan(db, goalId, { estimatedTotalCostCents: 9000 });
      setOrchestratorState(db, { phase: "plan_review", goalId, replanCount: 0, failedTaskId: null, failedError: null });

      const orc = makeOrchestrator(db);
      await orc.tick(); // rejection #1 -> planning

      // The "cheaper plan" attempt produced a plan under the ceiling.
      storePlan(db, goalId, { estimatedTotalCostCents: 800 });
      await orc.tick(); // planning -> plan_review

      const result = await orc.tick(); // plan_review -> executing
      expect(result.phase).toBe("executing");

      const goalRow = db.prepare("SELECT status FROM goals WHERE id = ?").get(goalId) as { status: string };
      expect(goalRow.status).toBe("active");
    });

    it("a valid under-budget plan resets the rejection counter so past rejections cannot poison future work", async () => {
      const goalId = insertGoal(db);
      insertTask(db, { goalId, title: "t1", description: "desc" });

      // One prior rejection already recorded for this goal.
      db.prepare("INSERT OR REPLACE INTO kv (key, value, updated_at) VALUES (?, ?, datetime('now'))")
        .run(`orchestrator.budget_rejections.${goalId}`, "1");

      storePlan(db, goalId, { estimatedTotalCostCents: 100 });
      setOrchestratorState(db, { phase: "plan_review", goalId, replanCount: 0, failedTaskId: null, failedError: null });

      const orc = makeOrchestrator(db);
      const result = await orc.tick();
      expect(result.phase).toBe("executing");

      // Counter must be cleared on approval: a later over-budget plan on this
      // goal gets a full bounded retry instead of being blocked immediately.
      const countRow = db.prepare("SELECT value FROM kv WHERE key = ?").get(`orchestrator.budget_rejections.${goalId}`);
      expect(countRow).toBeUndefined();

      // And a fresh over-budget plan on the same goal again gets the bounded
      // cheaper-plan attempt (planning), not an immediate pause.
      storePlan(db, goalId, { estimatedTotalCostCents: 9000 });
      setOrchestratorState(db, { phase: "plan_review", goalId, replanCount: 0, failedTaskId: null, failedError: null });
      const next = await orc.tick();
      expect(next.phase).toBe("planning");
    });
  });
});

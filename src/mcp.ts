import { createHash, randomUUID } from "node:crypto";
import path from "node:path";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod/v4";
import type { GatewayConfig } from "./config.js";
import { SHELLBRIDGE_VERSION } from "./version.js";
import {
  COMMAND_MAX_LENGTH,
  COMMAND_OUTPUT_MAX_BYTES,
  COMMAND_TIMEOUT_MAX_MS,
  DOCUMENT_MAX_BYTES,
  PROJECT_TASK_OUTPUT_MAX_BYTES,
  PROJECT_TASK_TIMEOUT_MAX_MS,
  SCRIPT_RUN_OUTPUT_MAX_BYTES,
  SCRIPT_RUN_TIMEOUT_MAX_MS,
  READ_SCOPE_MAX_LENGTH,
} from "./domain.js";

const pendingInitializations = new WeakMap<FastifyInstance, number>();
const gcTimers = new WeakMap<FastifyInstance, NodeJS.Timeout>();

interface McpSession {
  transport: StreamableHTTPServerTransport;
  server: McpServer;
  app: FastifyInstance;
  createdAt: number;
  lastUsedAt: number;
  inFlight: number;
}

const transports = new Map<string, McpSession>();

function sessionFingerprint(id: string): string {
  return createHash("sha256").update(id).digest("hex").slice(0, 12);
}

function sessionStats(app: FastifyInstance) {
  const sessions = [...transports.values()].filter((item) => item.app === app);
  return {
    retained_sessions: sessions.length,
    active_sessions: sessions.filter((item) => item.inFlight > 0).length,
    idle_sessions: sessions.filter((item) => item.inFlight === 0).length,
    pending_initializations: pendingInitializations.get(app) ?? 0,
  };
}

function logSession(app: FastifyInstance, event: string, details: Record<string, unknown> = {}): void {
  app.log.info({ component: "mcp_session", event, ...details, ...sessionStats(app) }, "MCP session lifecycle");
}

async function closeStoredSession(id: string, current: McpSession, reason: string): Promise<boolean> {
  if (transports.get(id) !== current) return false;
  transports.delete(id);
  const now = Date.now();
  logSession(current.app, "closing", {
    session: sessionFingerprint(id),
    reason,
    age_ms: now - current.createdAt,
    idle_ms: now - current.lastUsedAt,
    in_flight: current.inFlight,
  });
  try {
    await current.server.close();
    logSession(current.app, "closed", { session: sessionFingerprint(id), reason });
  } catch (error) {
    current.app.log.warn({
      component: "mcp_session",
      event: "close_failed",
      session: sessionFingerprint(id),
      reason,
      error: error instanceof Error ? error.message : String(error),
      ...sessionStats(current.app),
    }, "MCP session close failed");
  }
  return true;
}

async function pruneMcpSessions(app: FastifyInstance, ttlMs: number): Promise<void> {
  const cutoff = Date.now() - ttlMs;
  const closing: Promise<boolean>[] = [];
  for (const [id, current] of transports) {
    if (current.app !== app || current.inFlight > 0 || current.lastUsedAt >= cutoff) continue;
    closing.push(closeStoredSession(id, current, "stale_ttl"));
  }
  await Promise.all(closing);
}

function ensureMcpSessionGc(app: FastifyInstance, ttlMs: number): void {
  if (gcTimers.has(app)) return;
  const intervalMs = Math.max(10, Math.min(60_000, Math.floor(ttlMs / 2)));
  const timer = setInterval(() => {
    void pruneMcpSessions(app, ttlMs).catch((error) => {
      app.log.warn({
        component: "mcp_session",
        event: "gc_failed",
        error: error instanceof Error ? error.message : String(error),
        ...sessionStats(app),
      }, "MCP session GC failed");
    });
  }, intervalMs);
  timer.unref();
  gcTimers.set(app, timer);
  logSession(app, "gc_started", { ttl_ms: ttlMs, interval_ms: intervalMs });
}

function oldestIdleSession(app: FastifyInstance): [string, McpSession] | undefined {
  let oldest: [string, McpSession] | undefined;
  for (const entry of transports) {
    const [, current] = entry;
    if (current.app !== app || current.inFlight > 0) continue;
    if (!oldest || current.lastUsedAt < oldest[1].lastUsedAt
        || (current.lastUsedAt === oldest[1].lastUsedAt && current.createdAt < oldest[1].createdAt)) {
      oldest = entry;
    }
  }
  return oldest;
}

async function reserveSessionCapacity(app: FastifyInstance, limit: number): Promise<boolean> {
  const pending = pendingInitializations.get(app) ?? 0;
  const retained = sessionStats(app).retained_sessions;
  if (retained + pending < limit) {
    pendingInitializations.set(app, pending + 1);
    return true;
  }
  const oldest = oldestIdleSession(app);
  if (!oldest) return false;
  pendingInitializations.set(app, pending + 1);
  await closeStoredSession(oldest[0], oldest[1], "capacity_idle_lru");
  return true;
}

export async function closeMcpSessions(app: FastifyInstance): Promise<void> {
  const timer = gcTimers.get(app);
  if (timer) clearInterval(timer);
  gcTimers.delete(app);
  pendingInitializations.delete(app);
  const closing: Promise<boolean>[] = [];
  for (const [id, current] of transports) {
    if (current.app !== app) continue;
    closing.push(closeStoredSession(id, current, "app_close"));
  }
  await Promise.all(closing);
  logSession(app, "app_sessions_closed");
}

function ensureDestroySoon(request: FastifyRequest): void {
  const socket = request.raw.socket as typeof request.raw.socket & { destroySoon?: () => void };
  if (socket && typeof socket.destroySoon !== "function") {
    socket.destroySoon = () => undefined;
  }
}

function textResult(value: unknown, isError = false) {
  return { content: [{ type: "text" as const, text: typeof value === "string" ? value : JSON.stringify(value) }], ...(isError ? { isError: true } : {}) };
}

const readScopeSchema = z.string().min(1).max(READ_SCOPE_MAX_LENGTH).refine(
  (value) => path.isAbsolute(value) && !value.includes("\0"),
  "read_scope_must_be_an_absolute_path",
);

function createServer(app: FastifyInstance, config: GatewayConfig): McpServer {
  const server = new McpServer({ name: "shellbridge", version: SHELLBRIDGE_VERSION }, {
    instructions: "普通文件、源码和文本诊断使用 run_shell_command；检查某个项目时必须显式设置 read_scope，并确保 cwd 位于该范围内，cwd 只改变工作目录且不会扩大范围；省略 read_scope 才是兼容的完整配置根视图。同一诊断目标的相关只读命令应组合到一次调用，不要拆成并发沙箱。run_shell_batch 为顺序独立隔离，不是性能批处理。结构化错误包含 phase、reason 与 retryable；retryable=true 时可以合理重试。运行已经存在的测试或项目脚本使用 run_project_task，它在无网络临时副本中执行且不持久化输出。只有 .md/.txt 文档、结构化本地 Git 操作和用户明确要求的已有副作用脚本可以写入。不得用文档工具创建脚本，不得主动部署或重启。blocked 资源不能通过确认解锁。",
  });
  const internalHeaders = { authorization: `Bearer ${config.token}` };
  server.registerTool("run_shell_command", {
    title: "Run one ShellBridge command",
    description: "Run a complete Bash diagnostic command in a fresh read-only Bubblewrap sandbox. For project diagnostics, set read_scope to the one absolute project directory; the server mounts only that scope, rejects a cwd outside it, rejects symlink scopes, and never auto-expands to siblings or dependencies. If read_scope is omitted, the compatibility mode presents the configured complete read root and may spend significant time preparing its root-wide safety view; cwd does not reduce the root-wide view preparation. For one diagnostic goal, combine related diagnostic commands into one Bash command. Do not split them into parallel sandbox calls. If a structured preparation error reports retryable=true, retry reasonably. Pipes, loops, conditions, substitutions, awk/sed/find/xargs, and small Python or Node scripts are supported. The sandbox has no host write access, network, control sockets, or host process view.",
    inputSchema: { command: z.string().min(1).max(COMMAND_MAX_LENGTH), cwd: z.string().optional(), read_scope: readScopeSchema.optional(), timeout_ms: z.number().int().min(1).max(COMMAND_TIMEOUT_MAX_MS).optional(), max_output_bytes: z.number().int().min(1).max(COMMAND_OUTPUT_MAX_BYTES).optional() },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/shell/commands", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("run_shell_batch", {
    title: "Run an explicit ShellBridge batch",
    description: "Run an explicit sequence of complete Bash diagnostic commands with independent, sequential isolation. Each item may set its own absolute read_scope; when set, only that one directory is mounted and that item's cwd must remain inside it. Omitting read_scope preserves the configured complete-root compatibility view. This is not a performance optimization: every item gets a fresh sandbox and repeats safety-view preparation. If commands can safely share one diagnostic shell, prefer run_shell_command. The batch stops at the first failed item and reports its index plus completed results. It cannot create a write proposal.",
    inputSchema: { commands: z.array(z.strictObject({ command: z.string().min(1).max(COMMAND_MAX_LENGTH), cwd: z.string().optional(), read_scope: readScopeSchema.optional(), timeout_ms: z.number().int().min(1).max(COMMAND_TIMEOUT_MAX_MS).optional(), max_output_bytes: z.number().int().min(1).max(COMMAND_OUTPUT_MAX_BYTES).optional() })).min(1).max(10) },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/shell/batches", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("inspect_config", {
    title: "Inspect selected fields from a registered configuration",
    description: "Read only exact JSON Pointers or env variable names from an administrator-registered config target. Credentials are returned only as missing, empty, or set/redacted state and never as values.",
    inputSchema: z.strictObject({
      path: z.string().min(1).max(4096),
      format: z.enum(["json", "env"]),
      selectors: z.array(z.string().min(1).max(256)).min(1).max(32),
    }),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/inspect/config", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("run_project_task", {
    title: "Run an existing project task read-only",
    description: "Run one package.json script that already exists, or one existing shell/Python/Node/Go project script, inside a no-network Bubblewrap task sandbox. The project is copied to a command-lifetime writable tmpfs so caches, coverage, builds, and reports never change the host. Inline commands are not accepted and no proposal is created.",
    inputSchema: z.strictObject({
      cwd: z.string().min(1).max(4096),
      package_script: z.string().min(1).max(128).optional(),
      script_path: z.string().min(1).max(4096).optional(),
      args: z.array(z.string().max(4096)).max(100).optional(),
      timeout_ms: z.number().int().min(1).max(PROJECT_TASK_TIMEOUT_MAX_MS).optional(),
      max_output_bytes: z.number().int().min(1).max(PROJECT_TASK_OUTPUT_MAX_BYTES).optional(),
    }),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/tasks/run", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("write_text_document", {
    title: "Create or replace a Markdown or text document",
    description: "Consequential document write. Atomically create or replace only a .md or .txt regular file under /root. Parent directories may be created. Source, config, script, credential, blocked, and symlink targets are rejected. expected_hash protects updates from concurrent changes.",
    inputSchema: z.strictObject({
      path: z.string().min(1).max(4096),
      content: z.string().max(DOCUMENT_MAX_BYTES),
      expected_hash: z.string().regex(/^[a-f0-9]{64}$/).optional(),
    }),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/documents/write", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("patch_text_document", {
    title: "Patch a Markdown or text document",
    description: "Consequential document write. Apply exact structured text replacements to one existing .md or .txt regular file under /root using atomic replacement. Use expected_hash when modifying an observed file. Blocked resources and symlinks are always rejected.",
    inputSchema: z.strictObject({
      path: z.string().min(1).max(4096),
      replacements: z.array(z.strictObject({
        old_text: z.string().min(1),
        new_text: z.string(),
        replace_all: z.boolean().optional(),
      })).min(1).max(100),
      expected_hash: z.string().regex(/^[a-f0-9]{64}$/).optional(),
    }),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/documents/patch", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("move_text_document", {
    title: "Move or rename a Markdown or text document",
    description: "Consequential document write. Atomically move one .md or .txt regular file under /root to a new .md or .txt path. The destination must not exist. Blocked resources, non-document extensions, and symlinks are rejected.",
    inputSchema: z.strictObject({
      source: z.string().min(1).max(4096),
      destination: z.string().min(1).max(4096),
      expected_hash: z.string().regex(/^[a-f0-9]{64}$/).optional(),
    }),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/documents/move", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("get_git_status", {
    title: "Get complete local Git status",
    description: "Read the complete staged, unstaged, and untracked status of a real Git worktree under /root without contacting remotes.",
    inputSchema: z.strictObject({ repo: z.string().min(1).max(4096) }),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/git/status", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("git_stage", {
    title: "Stage local Git changes",
    description: "Consequential local Git write. Stage explicit paths, or all=true, in a real worktree under /root. It never contacts or changes remotes.",
    inputSchema: z.strictObject({
      repo: z.string().min(1).max(4096),
      paths: z.array(z.string().min(1).max(4096)).min(1).max(500).optional(),
      all: z.boolean().optional(),
    }),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/git/stage", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("git_unstage", {
    title: "Unstage local Git changes",
    description: "Consequential local Git write. Unstage explicit paths, or all=true, without changing worktree files. It does not run reset --hard or contact remotes.",
    inputSchema: z.strictObject({
      repo: z.string().min(1).max(4096),
      paths: z.array(z.string().min(1).max(4096)).min(1).max(500).optional(),
      all: z.boolean().optional(),
    }),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/git/unstage", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("prepare_git_commit", {
    title: "Prepare an immutable local Git commit",
    description: "Prepare, but do not execute, one exact local commit for explicit paths or all=true. The proposal freezes the repository, branch, HEAD, current index, worktree state, target index tree, message, and full file list. If pending, call execute_proposal with its approval_id.",
    inputSchema: z.strictObject({
      repo: z.string().min(1).max(4096),
      message: z.string().min(1).max(1000),
      paths: z.array(z.string().min(1).max(4096)).min(1).max(500).optional(),
      all: z.boolean().optional(),
    }),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/git/commits/prepare", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("prepare_existing_script_run", {
    title: "Prepare one existing side-effecting script run",
    description: "Use only when the user explicitly asks, or the current task necessarily requires it. Prepare an existing backup, export, deployment, restart, or maintenance script; never proactively deploy, restart, or maintain. Inline commands are rejected. The proposal freezes inode, content hash, interpreter, arguments, cwd, resource limits, and environment profile. If pending, call execute_proposal.",
    inputSchema: z.strictObject({
      script_path: z.string().min(1).max(4096),
      args: z.array(z.string().max(4096)).max(100).optional(),
      cwd: z.string().min(1).max(4096).optional(),
      impact_summary: z.string().min(4).max(1000),
      timeout_ms: z.number().int().min(1).max(SCRIPT_RUN_TIMEOUT_MAX_MS).optional(),
      max_output_bytes: z.number().int().min(1).max(SCRIPT_RUN_OUTPUT_MAX_BYTES).optional(),
    }),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/scripts/prepare", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("get_proposal", {
    title: "Get a ShellBridge proposal",
    description: "Use this to inspect the complete redacted preview and current status of an existing proposal.",
    inputSchema: { approval_id: z.string().uuid() },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async ({ approval_id }) => {
    const response = await app.inject({ method: "GET", url: `/v1/shell/approvals/${approval_id}`, headers: internalHeaders });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("execute_proposal", {
    title: "Execute one immutable ShellBridge proposal",
    description: "Consequential write tool. Call immediately after a prepare tool returns pending. Accepts only that approval_id and cannot add or override a command, cwd, path, or argument. The client should show its official confirmation UI. A refusal must stop the workflow; a successful result resumes it.",
    inputSchema: z.strictObject({ approval_id: z.string().uuid() }),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  }, async ({ approval_id }) => {
    const response = await app.inject({ method: "POST", url: `/v1/shell/approvals/${approval_id}/execute`, headers: internalHeaders });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("cancel_proposal", {
    title: "Cancel one pending ShellBridge proposal",
    description: "Cancel one pending immutable proposal so it can never execute. This changes proposal state but does not run the planned host action.",
    inputSchema: z.strictObject({ approval_id: z.string().uuid() }),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async ({ approval_id }) => {
    const response = await app.inject({ method: "POST", url: `/v1/shell/approvals/${approval_id}/cancel`, headers: internalHeaders });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("prepare_approval_smoke", {
    title: "Prepare the fixed approval UI smoke operation",
    description: "Prepare the fixed local-only approval smoke operation when a root administrator has temporarily enabled it. It accepts no path or shell input. If pending, immediately call execute_proposal with its approval_id.",
    inputSchema: z.strictObject({}),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async () => {
    const response = await app.inject({ method: "POST", url: "/v1/shell/approval-smoke", headers: internalHeaders });
    return textResult(response.body, response.statusCode >= 400);
  });
  return server;
}

export async function handleMcpRequest(app: FastifyInstance, config: GatewayConfig, request: FastifyRequest, reply: FastifyReply): Promise<void> {
  ensureDestroySoon(request);
  ensureMcpSessionGc(app, config.mcpSessionTtlMs);
  const sessionId = request.headers["mcp-session-id"] as string | undefined;
  const found = sessionId ? transports.get(sessionId) : undefined;
  const now = Date.now();
  const current = found?.app === app && (found.inFlight > 0 || found.lastUsedAt >= now - config.mcpSessionTtlMs)
    ? found
    : undefined;
  if (current) {
    current.inFlight += 1;
    current.lastUsedAt = now;
  }
  await pruneMcpSessions(app, config.mcpSessionTtlMs);
  const method = request.body && typeof request.body === "object" && "method" in request.body
    ? String((request.body as { method?: unknown }).method ?? "unknown").slice(0, 100)
    : request.method === "DELETE" ? "session/delete" : "unknown";
  if (!current && !sessionId && isInitializeRequest(request.body)) {
    if (!(await reserveSessionCapacity(app, config.mcpSessionLimit))) {
      logSession(app, "limit_reached", { limit: config.mcpSessionLimit, method });
      reply.code(429).send({ jsonrpc: "2.0", error: { code: -32000, message: "MCP session limit reached" }, id: null });
      return;
    }
    logSession(app, "initialization_reserved", { limit: config.mcpSessionLimit });
    let reservationHeld = true;
    let initializedSessionId: string | undefined;
    let disconnected = false;
    let disconnectCleanup: Promise<unknown> | undefined;
    let unstoredServerClose: Promise<void> | undefined;
    const releaseReservation = () => {
      if (!reservationHeld) return;
      reservationHeld = false;
      const remaining = (pendingInitializations.get(app) ?? 1) - 1;
      if (remaining <= 0) pendingInitializations.delete(app);
      else pendingInitializations.set(app, remaining);
    };
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      enableJsonResponse: true,
      onsessioninitialized: (id) => {
        initializedSessionId = id;
        releaseReservation();
        const now = Date.now();
        transports.set(id, { transport, server, app, createdAt: now, lastUsedAt: now, inFlight: 1 });
        logSession(app, "initialized", { session: sessionFingerprint(id), method });
      },
      onsessionclosed: (id) => {
        const closed = transports.get(id);
        if (!closed || closed.app !== app) return;
        transports.delete(id);
        logSession(app, "client_closed", {
          session: sessionFingerprint(id),
          age_ms: Date.now() - closed.createdAt,
          in_flight: closed.inFlight,
        });
      },
    });
    const server = createServer(app, config);
    const closeUnstoredServer = () => {
      unstoredServerClose ??= server.close().catch(() => undefined);
      return unstoredServerClose;
    };
    const markDisconnected = (event: "request_aborted" | "response_disconnected") => {
      if (disconnected) return;
      disconnected = true;
      logSession(app, event, {
        session: initializedSessionId ? sessionFingerprint(initializedSessionId) : undefined,
        method,
      });
      const initialized = initializedSessionId ? transports.get(initializedSessionId) : undefined;
      disconnectCleanup = initializedSessionId && initialized
        ? closeStoredSession(initializedSessionId, initialized, "initialization_disconnect")
        : closeUnstoredServer();
    };
    const onAborted = () => { markDisconnected("request_aborted"); };
    const onPrematureClose = () => {
      if (reply.raw.writableEnded) return;
      markDisconnected("response_disconnected");
    };
    const onSocketClose = () => {
      if (reply.raw.writableEnded) return;
      markDisconnected("response_disconnected");
    };
    request.raw.once("aborted", onAborted);
    reply.raw.once("close", onPrematureClose);
    request.raw.socket.once("close", onSocketClose);
    try {
      await server.connect(transport as any);
      reply.hijack();
      await transport.handleRequest(request.raw, reply.raw, request.body);
    } catch (error) {
      app.log.warn({
        component: "mcp_session",
        event: "initialization_failed",
        session: initializedSessionId ? sessionFingerprint(initializedSessionId) : undefined,
        method,
        disconnected,
        error: error instanceof Error ? error.message : String(error),
        ...sessionStats(app),
      }, "MCP session initialization failed");
      if (initializedSessionId) {
        const initialized = transports.get(initializedSessionId);
        if (initialized) await closeStoredSession(initializedSessionId, initialized, "initialization_failed");
      } else {
        await closeUnstoredServer();
      }
      throw error;
    } finally {
      request.raw.off("aborted", onAborted);
      reply.raw.off("close", onPrematureClose);
      request.raw.socket.off("close", onSocketClose);
      const reservationWasHeld = reservationHeld;
      releaseReservation();
      if (reservationWasHeld && !initializedSessionId) {
        logSession(app, "initialization_reservation_released", { disconnected });
      }
      if (initializedSessionId) {
        const initialized = transports.get(initializedSessionId);
        if (initialized) {
          initialized.inFlight = Math.max(0, initialized.inFlight - 1);
          initialized.lastUsedAt = Date.now();
          logSession(app, "request_finished", {
            session: sessionFingerprint(initializedSessionId),
            method,
            disconnected,
            in_flight: initialized.inFlight,
          });
          if (disconnected) await closeStoredSession(initializedSessionId, initialized, "initialization_disconnect");
        }
      } else {
        await closeUnstoredServer();
      }
      await disconnectCleanup;
    }
    return;
  }
  if (!current) {
    logSession(app, "invalid_session", { session: sessionId ? sessionFingerprint(sessionId) : undefined, method });
    reply.code(400).send({ jsonrpc: "2.0", error: { code: -32000, message: "MCP session is missing or invalid" }, id: null });
    return;
  }

  let disconnected = false;
  let disconnectCleanup: Promise<boolean> | undefined;
  const markDisconnected = (event: "request_aborted" | "response_disconnected") => {
    if (disconnected) return;
    disconnected = true;
    logSession(app, event, { session: sessionFingerprint(sessionId!), method });
    disconnectCleanup = closeStoredSession(sessionId!, current, "request_disconnect");
  };
  const onAborted = () => { markDisconnected("request_aborted"); };
  const onPrematureClose = () => {
    if (reply.raw.writableEnded) return;
    markDisconnected("response_disconnected");
  };
  const onSocketClose = () => {
    if (reply.raw.writableEnded) return;
    markDisconnected("response_disconnected");
  };
  request.raw.once("aborted", onAborted);
  reply.raw.once("close", onPrematureClose);
  request.raw.socket.once("close", onSocketClose);
  logSession(app, "request_started", {
    session: sessionFingerprint(sessionId!),
    method,
    in_flight: current.inFlight,
  });
  try {
    reply.hijack();
    await current.transport.handleRequest(request.raw, reply.raw, request.body);
  } catch (error) {
    app.log.warn({
      component: "mcp_session",
      event: "request_failed",
      session: sessionFingerprint(sessionId!),
      method,
      disconnected,
      error: error instanceof Error ? error.message : String(error),
      ...sessionStats(app),
    }, "MCP session request failed");
    throw error;
  } finally {
    request.raw.off("aborted", onAborted);
    reply.raw.off("close", onPrematureClose);
    request.raw.socket.off("close", onSocketClose);
    const retained = transports.get(sessionId!);
    if (retained === current) {
      current.inFlight = Math.max(0, current.inFlight - 1);
      current.lastUsedAt = Date.now();
      logSession(app, "request_finished", {
        session: sessionFingerprint(sessionId!),
        method,
        disconnected,
        in_flight: current.inFlight,
      });
      if (disconnected) await closeStoredSession(sessionId!, current, "request_disconnect");
    }
    await disconnectCleanup;
  }
}

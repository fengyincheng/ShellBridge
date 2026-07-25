import Fastify, { type FastifyInstance, type FastifyReply } from "fastify";
import formbody from "@fastify/formbody";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createConfig, type GatewayConfig } from "./config.js";
import { COMMAND_MAX_LENGTH, COMMAND_OUTPUT_DEFAULT_BYTES, COMMAND_OUTPUT_MAX_BYTES, COMMAND_TIMEOUT_DEFAULT_MS, COMMAND_TIMEOUT_MAX_MS, OWNER_PRINCIPAL_ID } from "./domain.js";
import { ProposalError, Store, proposalHash, type Proposal } from "./persistence.js";
import { closeMcpSessions, handleMcpRequest } from "./mcp.js";
import { OAuthService } from "./oauth.js";
import { getApprovalSmokeState, type SmokeState } from "./policy.js";
import { redact, registerExactRedactionSecrets } from "./redactor.js";
import { ConfigInspector } from "./config-inspector.js";
import { SandboxedShell } from "./sandboxed-shell.js";
import { DocumentWriter } from "./document-writer.js";
import { GitService, type GitCommitProposal } from "./git-service.js";
import { ProjectTaskRunner } from "./task-runner.js";
import { ExistingScriptRunner, type ExistingScriptProposal } from "./existing-script-runner.js";
import { SHELLBRIDGE_VERSION } from "./version.js";

export function createOpenApi(config: Pick<GatewayConfig, "publicBaseUrl">, version = SHELLBRIDGE_VERSION) {
  return {
    openapi: "3.1.0",
    info: { title: "ShellBridge", version, description: "Fast, safe, and auditable Linux VPS visibility for ChatGPT through MCP." },
    servers: [{ url: config.publicBaseUrl }],
    components: { securitySchemes: { bearerAuth: { type: "apiKey", in: "header", name: "Authorization", description: "REST administration uses the complete Bearer value; MCP clients use restricted OAuth." } } },
    security: [{ bearerAuth: [] }],
    paths: {
      "/v1/shell/commands": { post: { operationId: "runShellCommand", summary: "Run one Bash diagnostic in the read-only Bubblewrap sandbox" } },
      "/v1/shell/batches": { post: { operationId: "runShellBatch", summary: "Run an explicit diagnostic batch in separate read-only sandbox calls" } },
      "/v1/inspect/config": { post: { operationId: "inspectConfig", summary: "Read exact registered configuration fields with mandatory redaction" } },
      "/v1/tasks/run": { post: { operationId: "runProjectTask", summary: "Run an existing project task in a disposable writable copy" } },
      "/v1/documents/write": { post: { operationId: "writeTextDocument", "x-openai-isConsequential": true, summary: "Atomically write a Markdown or text document" } },
      "/v1/documents/patch": { post: { operationId: "patchTextDocument", "x-openai-isConsequential": true, summary: "Patch exact text in a Markdown or text document" } },
      "/v1/documents/move": { post: { operationId: "moveTextDocument", "x-openai-isConsequential": true, summary: "Move a Markdown or text document" } },
      "/v1/git/status": { post: { operationId: "getGitStatus", summary: "Read complete local Git status" } },
      "/v1/git/stage": { post: { operationId: "gitStage", "x-openai-isConsequential": true, summary: "Stage explicit local Git changes" } },
      "/v1/git/unstage": { post: { operationId: "gitUnstage", "x-openai-isConsequential": true, summary: "Unstage explicit local Git changes" } },
      "/v1/git/commits/prepare": { post: { operationId: "prepareGitCommit", summary: "Freeze one exact local Git commit proposal" } },
      "/v1/scripts/prepare": { post: { operationId: "prepareExistingScriptRun", "x-openai-isConsequential": true, summary: "Freeze one pre-existing side-effecting script proposal" } },
      "/v1/shell/approvals/{approval_id}/execute": { post: { operationId: "executeShellApproval", "x-openai-isConsequential": true, summary: "Execute one existing immutable proposal" } },
    },
  };
}

interface CommandInput {
  command: string;
  cwd?: string;
  timeout_ms?: number;
  max_output_bytes?: number;
}

interface ApprovalSmokeProposal extends SmokeState {
  kind: "approval_smoke";
  operation: "create_empty_file";
  filename: string;
}

function isValidCommandInput(input: unknown): input is CommandInput {
  if (!input || typeof input !== "object") return false;
  const item = input as Record<string, unknown>;
  return typeof item.command === "string" && item.command.length >= 1 && item.command.length <= COMMAND_MAX_LENGTH && !item.command.includes("\0")
    && (item.cwd === undefined || typeof item.cwd === "string")
    && (item.timeout_ms === undefined || (Number.isInteger(item.timeout_ms) && Number(item.timeout_ms) >= 1 && Number(item.timeout_ms) <= COMMAND_TIMEOUT_MAX_MS))
    && (item.max_output_bytes === undefined || (Number.isInteger(item.max_output_bytes) && Number(item.max_output_bytes) >= 1 && Number(item.max_output_bytes) <= COMMAND_OUTPUT_MAX_BYTES));
}

function validateSmokeProposal(
  payload: ApprovalSmokeProposal,
  config: GatewayConfig,
  resolveSmokeState: (config: GatewayConfig) => SmokeState,
): void {
  let current;
  try { current = resolveSmokeState(config); } catch { throw new ProposalError("approval_smoke_state_changed"); }
  if (payload.operation !== "create_empty_file"
    || !/^smoke-[0-9a-f-]{36}\.empty$/.test(payload.filename)
    || payload.directory !== current.directory
    || payload.enabled_file !== current.enabled_file
    || payload.enabled_dev !== current.enabled_dev
    || payload.enabled_ino !== current.enabled_ino
    || payload.enabled_mtime_ms !== current.enabled_mtime_ms
    || path.dirname(path.join(current.directory, payload.filename)) !== current.directory) {
    throw new ProposalError("approval_smoke_state_changed");
  }
}

type ExecutableProposalKind = "approval_smoke" | "git_commit" | "existing_script_run";

function validateProposalForExecution(
  proposal: Proposal,
  config: GatewayConfig,
  git: GitService,
  scripts: ExistingScriptRunner,
  resolveSmokeState: (config: GatewayConfig) => SmokeState,
): ExecutableProposalKind {
  const payload = proposal.payload as Record<string, unknown>;
  if (payload.kind === "approval_smoke") {
    validateSmokeProposal(payload as unknown as ApprovalSmokeProposal, config, resolveSmokeState);
    return "approval_smoke";
  }
  if (payload.kind === "git_commit") {
    git.validateCommitProposal(payload as unknown as GitCommitProposal);
    return "git_commit";
  }
  if (payload.kind === "existing_script_run") {
    scripts.validate(payload as unknown as ExistingScriptProposal);
    return "existing_script_run";
  }
  throw new ProposalError("unsupported_proposal_kind");
}

function proposalErrorReply(error: unknown, reply: FastifyReply) {
  const code = error instanceof ProposalError ? error.code : error instanceof Error ? error.message : "approval_not_executable";
  if (code === "approval_not_found" || code === "approval_principal_mismatch") return reply.code(404).send({ error: "approval_not_found" });
  if (code === "blocked_operation" || code === "blocked_resource" || code.endsWith("_disabled")) return reply.code(403).send({ classification: "blocked", status: "blocked", error: code });
  return reply.code(409).send({ error: code });
}

function capabilityEnabled(config: GatewayConfig, capability: "document" | "git" | "script"): boolean {
  if (!config.writeActionsEnabled) return false;
  if (capability === "document") return config.documentWritesEnabled;
  if (capability === "git") return config.localGitWritesEnabled;
  return config.existingScriptRunsEnabled;
}

function capabilityError(capability: "document" | "git" | "script"): string {
  return capability === "document" ? "document_writes_disabled"
    : capability === "git" ? "local_git_writes_disabled"
      : "existing_script_runs_disabled";
}

function operationErrorReply(error: unknown, reply: FastifyReply) {
  const code = error instanceof Error && /^[a-z0-9_: ./'-]+$/i.test(error.message) ? error.message : "operation_failed";
  if (code === "sandbox_unavailable" || code.startsWith("sandbox_unavailable:")) return reply.code(503).send({ error: "sandbox_unavailable" });
  if (code.includes("blocked") || code.includes("outside") || code.includes("not_allowed") || code.endsWith("_disabled")) {
    return reply.code(403).send({ error: code });
  }
  return reply.code(400).send({ error: code });
}

interface AppDependencies {
  sandboxedShell?: Pick<SandboxedShell, "run">;
  configInspector?: Pick<ConfigInspector, "inspect">;
  resolveApprovalSmokeState?: (config: GatewayConfig) => SmokeState;
}

export async function buildApp(config: GatewayConfig = createConfig(), dependencies: AppDependencies = {}): Promise<FastifyInstance> {
  registerExactRedactionSecrets([
    config.token,
    config.oauthOwnerSecret,
    config.encryptionKey.toString("base64"),
    config.encryptionKey.toString("base64url"),
    config.encryptionKey.toString("hex"),
  ]);
  fs.mkdirSync(path.dirname(config.databasePath), { recursive: true });
  fs.mkdirSync(config.defaultCwd, { recursive: true, mode: 0o700 });
  const app = Fastify({ logger: false, bodyLimit: 256 * 1024 });
  await app.register(formbody);
  const store = new Store(config);
  const oauth = new OAuthService(config);
  const configInspector = dependencies.configInspector ?? new ConfigInspector({
    helperPath: config.nativeHelperPath,
    registeredTargets: config.inspectConfigTargets,
    registeredRoots: config.inspectConfigRoots,
    disclosedValuesByTarget: config.inspectConfigDisclosures,
    maxBytes: 64 * 1024,
    timeoutMs: 2_000,
  });
  let sandboxedShell = dependencies.sandboxedShell;
  if (!sandboxedShell) {
    try {
      const concreteShell = new SandboxedShell({
        helperPath: config.nativeHelperPath,
        seccompPath: config.seccompFilterPath,
        bwrapPath: config.bwrapPath,
        readRoots: config.sandboxReadRoots,
        blockedPaths: config.sandboxBlockedPaths,
        observerUid: config.observerUid,
        observerGid: config.observerGid,
        cgroupRoot: config.sandboxCgroupRoot,
        requireCgroup: config.sandboxRequireCgroup,
      });
      await concreteShell.initialize();
      sandboxedShell = concreteShell;
    } catch {
      sandboxedShell = { run: async () => { throw new Error("sandbox_unavailable"); } };
    }
  }
  const documents = new DocumentWriter(config.operationRoot, config.sandboxBlockedPaths);
  const git = new GitService(config.operationRoot, config.sandboxBlockedPaths);
  const projectTasks = new ProjectTaskRunner(config.operationRoot, config.sandboxBlockedPaths, sandboxedShell);
  const existingScripts = new ExistingScriptRunner(config.operationRoot, config.sandboxBlockedPaths);
  const resolveApprovalSmokeState = dependencies.resolveApprovalSmokeState ?? getApprovalSmokeState;
  const registrationAttempts = new Map<string, { count: number; resetAt: number }>();
  const consentFailures = new Map<string, { count: number; resetAt: number }>();
  const limited = (bucket: Map<string, { count: number; resetAt: number }>, key: string, maximum: number, windowMs: number) => {
    const now = Date.now(); const current = bucket.get(key);
    if (!current || current.resetAt <= now) { bucket.set(key, { count: 1, resetAt: now + windowMs }); return false; }
    current.count += 1; return current.count > maximum;
  };
  app.addHook("onClose", async () => { store.close(); oauth.close(); });
  app.addHook("preHandler", async (request, reply) => {
    if (request.url === "/openapi.json" || request.url.startsWith("/.well-known/") || request.url.startsWith("/oauth/")) return;
    const auth = request.headers.authorization;
    const bearer = auth?.startsWith("Bearer ") ? auth.slice(7) : "";
    if (auth !== `Bearer ${config.token}` && !(request.url.startsWith("/mcp") && oauth.validateAccess(bearer, `${config.publicBaseUrl}/mcp`))) {
      if (request.url.startsWith("/mcp")) reply.header("WWW-Authenticate", `Bearer resource_metadata="${config.publicBaseUrl}/.well-known/oauth-protected-resource/mcp"`);
      return reply.code(401).send({ error: "unauthorized" });
    }
  });
  app.get("/health", async () => ({
    status: "ok",
    version: SHELLBRIDGE_VERSION,
    write_actions_enabled: config.writeActionsEnabled,
    document_writes_enabled: config.documentWritesEnabled,
    local_git_writes_enabled: config.localGitWritesEnabled,
    existing_script_runs_enabled: config.existingScriptRunsEnabled,
  }));
  app.get("/openapi.json", async () => createOpenApi(config));
  app.get("/.well-known/oauth-authorization-server", async () => oauth.metadata());
  app.get("/.well-known/oauth-protected-resource/mcp", async () => oauth.protectedResourceMetadata());
  app.post("/oauth/register", async (request, reply) => {
    if (limited(registrationAttempts, request.ip, 10, 60 * 60_000)) { oauth.audit("client_registration", null, "rate_limited"); return reply.code(429).send({ error: "rate_limited" }); }
    try { return reply.code(201).send(oauth.registerClient(request.body)); } catch (error: any) { oauth.audit("client_registration", null, "rejected"); return reply.code(400).send({ error: error.message }); }
  });
  app.get<{ Querystring: Record<string, string> }>("/oauth/authorize", async (request, reply) => {
    let details; try { details = oauth.validateAuthorization(request.query); } catch (error: any) { return reply.code(400).send({ error: error.message }); }
    const hidden = Object.entries(request.query).map(([key, value]) => `<input type="hidden" name="${key.replace(/[^a-z_]/gi, "")}" value="${String(value).replace(/[&<>\"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!)}">`).join("");
    const display = (value: string) => value.replace(/[&<>\"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);
    const redirectOrigin = new URL(details.redirectUri).origin;
    reply.header("Cache-Control", "no-store").header("Content-Security-Policy", `default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${redirectOrigin}; frame-ancestors 'none'`).header("X-Frame-Options", "DENY").type("text/html").send(`<!doctype html><meta charset="utf-8"><title>Authorize ShellBridge</title><h1>Authorize ShellBridge MCP</h1><dl><dt>Client</dt><dd>${display(details.clientName)}</dd><dt>Redirect</dt><dd>${display(details.redirectUri)}</dd><dt>Scopes</dt><dd>${display(details.scope)}</dd></dl><p>This grants diagnostic access. Restricted writes still require enabled local switches and the client's write confirmation.</p><form method="post" action="/oauth/authorize">${hidden}<label>Owner consent secret <input type="password" name="owner_secret" required autocomplete="current-password"></label><button type="submit">Authorize</button></form>`);
  });
  app.post<{ Body: Record<string, string> }>("/oauth/authorize", async (request, reply) => {
    try {
      const key = request.ip;
      if (limited(consentFailures, key, 5, 15 * 60_000)) { oauth.audit("owner_consent", request.body.client_id ?? null, "rate_limited"); return reply.code(429).send({ error: "rate_limited" }); }
      if (!oauth.ownerSecretMatches(request.body.owner_secret ?? "")) { oauth.audit("owner_consent", request.body.client_id ?? null, "rejected"); await new Promise((resolve) => setTimeout(resolve, 500)); return reply.code(401).send({ error: "access_denied" }); }
      consentFailures.delete(key);
      const result = oauth.issueCode(request.body); const url = new URL(result.redirectUri); url.searchParams.set("code", result.code); if (request.body.state) url.searchParams.set("state", request.body.state);
      return reply.redirect(url.toString(), 302);
    } catch (error: any) { oauth.audit("authorization_request", request.body.client_id ?? null, "rejected"); return reply.code(400).send({ error: error.message }); }
  });
  app.post<{ Body: Record<string, string> }>("/oauth/token", async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    oauth.audit("token_request", request.body.client_id ?? null, "received");
    try {
      if (request.body.grant_type === "authorization_code") return reply.send(oauth.exchangeCode(request.body));
      if (request.body.grant_type === "refresh_token") return reply.send(oauth.refresh(request.body));
      oauth.audit("token_request", request.body.client_id ?? null, "unsupported_grant_type");
      return reply.code(400).send({ error: "unsupported_grant_type" });
    } catch (error: any) { oauth.audit("token_request", request.body.client_id ?? null, "rejected"); return reply.code(400).send({ error: error.message }); }
  });
  app.post("/mcp", async (request, reply) => handleMcpRequest(app, config, request, reply));
  app.delete("/mcp", async (request, reply) => handleMcpRequest(app, config, request, reply));
  app.addHook("onClose", async () => closeMcpSessions(app));
  app.post<{ Body: { path?: unknown; format?: unknown; selectors?: unknown } }>("/v1/inspect/config", async (request, reply) => {
    const { path: requestedPath, format, selectors } = request.body ?? {};
    if (typeof requestedPath !== "string" || !["json", "env"].includes(String(format))
        || !Array.isArray(selectors) || selectors.some((item) => typeof item !== "string")) {
      return reply.code(400).send({ error: "invalid_request" });
    }
    try {
      return reply.send(await configInspector.inspect({
        path: requestedPath,
        format: format as "json" | "env",
        selectors: selectors as string[],
      }));
    } catch (error) {
      const code = error instanceof Error && [
        "config_target_not_registered", "config_read_failed", "invalid_utf8", "invalid_format",
        "invalid_selector", "invalid_selectors",
      ].includes(error.message) ? error.message : "config_inspection_failed";
      return reply.code(code === "config_target_not_registered" ? 403 : 400).send({ error: code });
    }
  });
  app.post<{ Body: CommandInput }>("/v1/shell/commands", async (request, reply) => {
    if (!isValidCommandInput(request.body)) return reply.code(400).send({ error: "invalid_request" });
    try {
      const result = await sandboxedShell.run({
        command: request.body.command,
        cwd: path.resolve(request.body.cwd ?? config.defaultCwd),
        timeoutMs: request.body.timeout_ms ?? COMMAND_TIMEOUT_DEFAULT_MS,
        maxOutputBytes: request.body.max_output_bytes ?? COMMAND_OUTPUT_DEFAULT_BYTES,
      });
      return reply.send({
        classification: "read_only",
        execution_channel: "sandboxed_read_shell",
        status: result.exitCode === 0 ? "completed" : "failed",
        stdout: result.stdout,
        stderr: result.stderr,
        exit_code: result.exitCode,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      if (message === "cwd_outside_sandbox_roots" || message === "invalid_command" || message === "invalid_timeout" || message === "invalid_output_limit") {
        return reply.code(400).send({ error: message });
      }
      return reply.code(503).send({ error: message.startsWith("sandbox_output_limit_exceeded") ? "sandbox_output_limit_exceeded" : "sandbox_unavailable" });
    }
  });
  app.post<{ Body: { commands: CommandInput[] } }>("/v1/shell/batches", async (request, reply) => {
    const commands = request.body?.commands;
    if (!Array.isArray(commands) || commands.length === 0 || commands.length > 10) return reply.code(400).send({ error: "commands_must_contain_1_to_10_items" });
    if (commands.some((item) => !isValidCommandInput(item))) return reply.code(400).send({ error: "invalid_command_item" });
    const results = [];
    for (const command of commands) {
      try {
        const result = await sandboxedShell.run({
          command: command.command,
          cwd: path.resolve(command.cwd ?? config.defaultCwd),
          timeoutMs: command.timeout_ms ?? COMMAND_TIMEOUT_DEFAULT_MS,
          maxOutputBytes: command.max_output_bytes ?? COMMAND_OUTPUT_DEFAULT_BYTES,
        });
        results.push({ classification: "read_only", execution_channel: "sandboxed_read_shell", status: result.exitCode === 0 ? "completed" : "failed", stdout: result.stdout, stderr: result.stderr, exit_code: result.exitCode });
        if (result.exitCode !== 0) break;
      } catch {
        return reply.code(503).send({ error: "sandbox_unavailable" });
      }
    }
    return reply.send({ classification: "read_only", execution_channel: "sandboxed_read_shell", status: "completed", results });
  });
  app.post<{ Body: { path: string; content: string; expected_hash?: string } }>("/v1/documents/write", async (request, reply) => {
    if (!capabilityEnabled(config, "document")) return reply.code(403).send({ error: capabilityError("document") });
    try {
      const result = documents.write(request.body);
      store.auditAction("document_write", result.path, { hash: result.hash }, "completed");
      return reply.send({ classification: "document_write", status: "completed", ...result });
    } catch (error) { return operationErrorReply(error, reply); }
  });
  app.post<{ Body: { path: string; replacements: Array<{ old_text: string; new_text: string; replace_all?: boolean }>; expected_hash?: string } }>("/v1/documents/patch", async (request, reply) => {
    if (!capabilityEnabled(config, "document")) return reply.code(403).send({ error: capabilityError("document") });
    try {
      const result = documents.patch(request.body);
      store.auditAction("document_patch", result.path, { hash: result.hash }, "completed");
      return reply.send({ classification: "document_write", status: "completed", ...result });
    } catch (error) { return operationErrorReply(error, reply); }
  });
  app.post<{ Body: { source: string; destination: string; expected_hash?: string } }>("/v1/documents/move", async (request, reply) => {
    if (!capabilityEnabled(config, "document")) return reply.code(403).send({ error: capabilityError("document") });
    try {
      const result = documents.move(request.body);
      store.auditAction("document_move", result.path, { previous_path: result.previous_path, hash: result.hash }, "completed");
      return reply.send({ classification: "document_write", status: "completed", ...result });
    } catch (error) { return operationErrorReply(error, reply); }
  });
  app.post<{ Body: { repo: string; paths?: string[]; all?: boolean } }>("/v1/git/stage", async (request, reply) => {
    if (!capabilityEnabled(config, "git")) return reply.code(403).send({ error: capabilityError("git") });
    try {
      const result = git.stage(request.body);
      store.auditAction("git_stage", result.repo, { paths: request.body.paths, all: request.body.all }, "completed");
      return reply.send({ classification: "local_git_write", status: "completed", ...result });
    } catch (error) { return operationErrorReply(error, reply); }
  });
  app.post<{ Body: { repo: string } }>("/v1/git/status", async (request, reply) => {
    try { return reply.send({ classification: "read_only", status: "completed", ...git.status(request.body.repo) }); }
    catch (error) { return operationErrorReply(error, reply); }
  });
  app.post<{ Body: { repo: string; paths?: string[]; all?: boolean } }>("/v1/git/unstage", async (request, reply) => {
    if (!capabilityEnabled(config, "git")) return reply.code(403).send({ error: capabilityError("git") });
    try {
      const result = git.unstage(request.body);
      store.auditAction("git_unstage", result.repo, { paths: request.body.paths, all: request.body.all }, "completed");
      return reply.send({ classification: "local_git_write", status: "completed", ...result });
    } catch (error) { return operationErrorReply(error, reply); }
  });
  app.post<{ Body: { repo: string; message: string; paths?: string[]; all?: boolean } }>("/v1/git/commits/prepare", async (request, reply) => {
    try {
      const payload = git.prepareCommit(request.body);
      const expires = new Date(Date.now() + config.proposalTtlMs).toISOString();
      const id = store.createProposal(payload, proposalHash(payload), expires, OWNER_PRINCIPAL_ID);
      return reply.code(202).send({
        classification: "approval_required",
        status: "pending",
        approval_id: id,
        proposal: payload,
        expires_at: expires,
      });
    } catch (error) { return operationErrorReply(error, reply); }
  });
  app.post<{ Body: {
    cwd: string;
    package_script?: string;
    script_path?: string;
    args?: string[];
    timeout_ms?: number;
    max_output_bytes?: number;
  } }>("/v1/tasks/run", async (request, reply) => {
    try { return reply.send(await projectTasks.run(request.body)); }
    catch (error) { return operationErrorReply(error, reply); }
  });
  app.post<{ Body: {
    script_path: string;
    args?: string[];
    cwd?: string;
    impact_summary: string;
    timeout_ms?: number;
    max_output_bytes?: number;
  } }>("/v1/scripts/prepare", async (request, reply) => {
    if (!capabilityEnabled(config, "script")) return reply.code(403).send({ error: capabilityError("script") });
    try {
      const payload = existingScripts.prepare(request.body);
      const expires = new Date(Date.now() + config.proposalTtlMs).toISOString();
      const id = store.createProposal(payload, proposalHash(payload), expires, OWNER_PRINCIPAL_ID);
      store.auditAction("existing_script_prepare", payload.script_path, { script_hash: payload.script_hash, argument_count: payload.args.length }, "pending");
      return reply.code(202).send({
        classification: "approval_required",
        status: "pending",
        approval_id: id,
        proposal: {
          kind: payload.kind,
          script_path: payload.script_path,
          script_hash: payload.script_hash,
          interpreter: payload.interpreter,
          arguments: { count: payload.args.length, hash: crypto.createHash("sha256").update(JSON.stringify(payload.args)).digest("hex") },
          cwd: payload.cwd,
          environment_profile: payload.environment_profile,
          impact_summary: payload.impact_summary,
        },
        expires_at: expires,
      });
    } catch (error) { return operationErrorReply(error, reply); }
  });
  app.post("/v1/shell/approval-smoke", async (_request, reply) => {
    let smoke;
    try { smoke = resolveApprovalSmokeState(config); } catch { return reply.code(409).send({ error: "approval_smoke_disabled" }); }
    const payload: ApprovalSmokeProposal = { kind: "approval_smoke", operation: "create_empty_file", filename: `smoke-${crypto.randomUUID()}.empty`, ...smoke };
    const expires = new Date(Date.now() + config.proposalTtlMs).toISOString();
    const id = store.createProposal(payload, proposalHash(payload), expires, OWNER_PRINCIPAL_ID);
    return reply.code(202).send({ classification: "approval_required", status: "pending", approval_id: id, proposal: { kind: payload.kind, operation: payload.operation, filename: payload.filename, directory: payload.directory }, expires_at: expires });
  });
  app.get<{ Params: { approval_id: string } }>("/v1/shell/approvals/:approval_id", async (request, reply) => {
    try {
      const proposal = store.getProposal(request.params.approval_id);
      if (!proposal || proposal.principal_id !== OWNER_PRINCIPAL_ID) return reply.code(404).send({ error: "approval_not_found" });
      const payload = proposal.payload as Record<string, unknown>;
      const preview = payload.kind === "existing_script_run"
        ? {
          ...payload,
          args: undefined,
          arguments: {
            count: Array.isArray(payload.args) ? payload.args.length : 0,
            hash: crypto.createHash("sha256").update(JSON.stringify(payload.args ?? [])).digest("hex"),
          },
        }
        : payload;
      return reply.send({ approval_id: proposal.id, status: proposal.state, hash: proposal.hash, expires_at: proposal.expires_at, proposal: JSON.parse(redact(JSON.stringify(preview))), ...(proposal.result === undefined ? {} : { result: proposal.result }) });
    } catch (error) { return proposalErrorReply(error, reply); }
  });
  app.post<{ Params: { approval_id: string } }>("/v1/shell/approvals/:approval_id/cancel", async (request, reply) => {
    return store.cancelProposal(request.params.approval_id) ? reply.send({ approval_id: request.params.approval_id, status: "cancelled" }) : reply.code(409).send({ error: "approval_not_cancellable" });
  });
  app.post<{ Params: { approval_id: string }; Body: unknown }>("/v1/shell/approvals/:approval_id/execute", async (request, reply) => {
    if (request.body !== undefined && (typeof request.body !== "object" || request.body === null || Object.keys(request.body).length !== 0)) return reply.code(400).send({ error: "invalid_request" });
    try {
      const current = store.getProposal(request.params.approval_id);
      if (!current || current.principal_id !== OWNER_PRINCIPAL_ID) return reply.code(404).send({ error: "approval_not_found" });
      if (current.state !== "pending") return reply.code(409).send({ error: "approval_not_executable", status: current.state });
      const currentKind = (current.payload as { kind?: string }).kind;
      if (!config.writeActionsEnabled) return reply.code(403).send({ error: "write_actions_disabled" });
      if (currentKind === "git_commit" && !config.localGitWritesEnabled) return reply.code(403).send({ error: "local_git_writes_disabled" });
      if (currentKind === "existing_script_run" && !config.existingScriptRunsEnabled) return reply.code(403).send({ error: "existing_script_runs_disabled" });
      validateProposalForExecution(current, config, git, existingScripts, resolveApprovalSmokeState);
      const claimed = store.claimProposal(request.params.approval_id, OWNER_PRINCIPAL_ID, (proposal) => {
        validateProposalForExecution(proposal, config, git, existingScripts, resolveApprovalSmokeState);
      });
      const payload = claimed.payload as ApprovalSmokeProposal | GitCommitProposal | ExistingScriptProposal;
      try {
        let result;
        if (payload.kind === "approval_smoke") {
          const target = path.join(payload.directory, payload.filename);
          const descriptor = fs.openSync(target, "wx", 0o600);
          fs.closeSync(descriptor);
          result = { classification: "approval_required", status: "completed", stdout: redact(`Created empty approval smoke file ${target}\n`), stderr: "", exit_code: 0 };
        } else if (payload.kind === "git_commit") {
          result = { ...git.executeCommit(payload), classification: "approval_required", status: "completed" };
          store.auditAction("git_commit", payload.repo, { commit: result.commit, files: payload.files }, "completed");
        } else {
          result = await existingScripts.execute(payload);
          store.auditAction("existing_script_run", payload.script_path, {
            script_hash: payload.script_hash,
            argument_count: payload.args.length,
            exit_code: result.exit_code,
          }, result.status);
        }
        store.finishProposal(claimed.id, "completed", result);
        return reply.send({ approval_id: claimed.id, ...result });
      } catch (error: any) {
        const result = { classification: "approval_required", status: "failed", stdout: "", stderr: redact(error.message ?? "proposal_execution_failed"), exit_code: 1 };
        if (payload.kind === "existing_script_run") {
          store.auditAction("existing_script_run", payload.script_path, {
            script_hash: payload.script_hash,
            argument_count: payload.args.length,
          }, "failed");
        }
        store.finishProposal(claimed.id, "failed", result);
        return reply.send({ approval_id: claimed.id, ...result });
      }
    } catch (error) { return proposalErrorReply(error, reply); }
  });
  return app;
}

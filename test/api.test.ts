import { afterEach, describe, expect, test } from "vitest";
import { createCipheriv, createHash, randomBytes } from "node:crypto";
import Database from "better-sqlite3";
import path from "node:path";
import { createTestApp, type TestApp } from "./support/test-app.js";

const apps: TestApp[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((item) => item.close()));
});

async function initializeMcp(app: TestApp) {
  const headers = { ...app.authHeaders, accept: "application/json, text/event-stream", "content-type": "application/json" };
  const initialize = await app.fastify.inject({
    method: "POST",
    url: "/mcp",
    headers,
    payload: { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "test", version: "1.0.0" } } },
  });
  expect(initialize.statusCode).toBe(200);
  return { headers: { ...headers, "mcp-session-id": initialize.headers["mcp-session-id"] as string } };
}

function sealTestProposal(payload: unknown): string {
  const key = Buffer.alloc(32, 7);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const body = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64");
}

function databasePath(app: TestApp): string {
  return path.join(path.dirname(app.fixtureDir), "shellbridge.db");
}

describe("ShellBridge command API", () => {
  test("uses one runtime base URL and reports conservative write defaults", async () => {
    const app = await createTestApp({
      writeActionsEnabled: false,
      documentWritesEnabled: false,
      localGitWritesEnabled: false,
      existingScriptRunsEnabled: false,
    });
    apps.push(app);

    const health = await app.fastify.inject({ method: "GET", url: "/health", headers: app.authHeaders });
    expect(health.statusCode).toBe(200);
    expect(health.json()).toMatchObject({
      version: "0.3.0",
      write_actions_enabled: false,
      document_writes_enabled: false,
      local_git_writes_enabled: false,
      existing_script_runs_enabled: false,
    });
    const schema = await app.fastify.inject({ method: "GET", url: "/openapi.json" });
    expect(schema.json()).toMatchObject({
      info: { version: "0.3.0" },
      servers: [{ url: "https://bridge.example.test" }],
    });
    const authorization = await app.fastify.inject({
      method: "GET",
      url: "/.well-known/oauth-authorization-server",
    });
    expect(authorization.json().issuer).toBe("https://bridge.example.test");
    const resource = await app.fastify.inject({
      method: "GET",
      url: "/.well-known/oauth-protected-resource/mcp",
    });
    expect(resource.json().resource).toBe("https://bridge.example.test/mcp");
    const unauthorized = await app.fastify.inject({ method: "GET", url: "/health" });
    expect(unauthorized.statusCode).toBe(401);
  });

  test("executes an ordinary read without creating an approval", async () => {
    const app = await createTestApp();
    apps.push(app);

    const response = await app.injectCommand({
      command: "printf hello",
      cwd: app.fixtureDir,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      classification: "read_only",
      status: "completed",
      stdout: "hello",
    });
  });

  test("inspects registered config selectors but never returns an API key", async () => {
    const app = await createTestApp({
      files: {
        "service.json":
          '{"SERVICE_API_KEY":"test-secret-never-return","SERVICE_BASE_URL":"https://api.example.test","model":"diagnostic-model"}',
      },
    });
    apps.push(app);

    const response = await app.fastify.inject({
      method: "POST",
      url: "/v1/inspect/config",
      headers: app.authHeaders,
      payload: {
        path: path.join(app.fixtureDir, "service.json"),
        format: "json",
        selectors: ["/SERVICE_API_KEY", "/SERVICE_BASE_URL", "/model"],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      status: "completed",
      fields: [
        { selector: "/SERVICE_API_KEY", status: "set", redacted: true },
        { selector: "/SERVICE_BASE_URL", status: "set", value: "https://api.example.test" },
        { selector: "/model", status: "set", value: "diagnostic-model" },
      ],
    });
    const wire = response.body;
    expect(wire).toContain("SERVICE_API_KEY");
    expect(wire).toContain("SERVICE_BASE_URL");
    expect(wire).toContain("diagnostic-model");
    expect(wire).not.toContain("test-secret-never-return");
    const db = new Database(databasePath(app), { readonly: true });
    expect(db.prepare("SELECT COUNT(*) AS count FROM proposals").get()).toEqual({ count: 0 });
    db.close();
    const databaseBytes = await (await import("node:fs/promises")).readFile(databasePath(app));
    expect(databaseBytes.toString("utf8")).not.toContain("test-secret-never-return");
  });

  test("lets the sandbox deny a modifying command without creating a proposal", async () => {
    const app = await createTestApp();
    apps.push(app);

    const response = await app.injectCommand({
      command: "touch should-not-exist",
      cwd: app.fixtureDir,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      classification: "read_only",
      execution_channel: "sandboxed_read_shell",
      status: "failed",
    });
    expect(await app.exists("should-not-exist")).toBe(false);
    const db = new Database(databasePath(app), { readonly: true });
    expect(db.prepare("SELECT COUNT(*) AS count FROM proposals").get()).toEqual({ count: 0 });
    db.close();
  });

  test("classifies df -hT as read_only, returns real output, and creates no proposal", async () => {
    const app = await createTestApp();
    apps.push(app);

    const response = await app.injectCommand({ command: "df -hT .", cwd: app.fixtureDir });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ classification: "read_only", status: "completed", exit_code: 0 });
    expect(response.json().stdout).toContain("Filesystem");
    const db = new Database(databasePath(app), { readonly: true });
    const count = db.prepare("SELECT COUNT(*) AS count FROM proposals").get() as { count: number };
    db.close();
    expect(count.count).toBe(0);
  });

  test("mounts only the administrator-registered cwd even for system queries", async () => {
    const app = await createTestApp();
    apps.push(app);

    const response = await app.injectCommand({ command: "df -hT .", cwd: app.fixtureDir });
    expect(response.statusCode).toBe(200);
    const defaulted = await app.injectCommand({ command: "uptime" });
    expect(defaulted.statusCode).toBe(200);
    const deniedWrite = await app.injectCommand({ command: "touch default-target" });
    expect(deniedWrite.statusCode).toBe(200);
    expect(deniedWrite.json().status).toBe("failed");
  });

  test("resolves cwd-dependent relative targets before applying path policy", async () => {
    const app = await createTestApp({ files: { "inside.txt": "inside" } });
    apps.push(app);

    const inside = await app.injectCommand({ command: "cat inside.txt", cwd: app.fixtureDir });
    expect(inside.statusCode).toBe(200);
    expect(inside.json().stdout).toBe("inside");

    const outsideRead = await app.injectCommand({ command: "cat passwd", cwd: "/etc" });
    expect(outsideRead.statusCode).toBe(400);
    expect(outsideRead.json()).toMatchObject({ error: "cwd_outside_sandbox_roots" });

    const relativeGit = await app.injectCommand({ command: "git status", cwd: "/root" });
    expect(relativeGit.statusCode).toBe(400);
    expect(relativeGit.json()).toMatchObject({ error: "cwd_outside_sandbox_roots" });
  });

  test("hides blocked host resources while allowing opaque code inside the sandbox", async () => {
    const app = await createTestApp();
    apps.push(app);
    const secret = await app.injectCommand({ command: "cat /etc/shadow", cwd: app.fixtureDir });
    expect(secret.statusCode).toBe(200);
    expect(secret.json()).toMatchObject({ status: "failed" });
    expect(secret.body).not.toContain("root:");
    const opaque = await app.injectCommand({ command: "python3 -c \"print('x')\"", cwd: app.fixtureDir });
    expect(opaque.statusCode).toBe(200);
    expect(opaque.json()).toMatchObject({ classification: "read_only", status: "completed", stdout: "x\n" });
  });

  test("keeps explicit batches separate and applies aggregate classification", async () => {
    const app = await createTestApp({ files: { "a.txt": "a" } });
    apps.push(app);
    const batch = await app.fastify.inject({
      method: "POST",
      url: "/v1/shell/batches",
      headers: app.authHeaders,
      payload: { commands: [{ command: "cat a.txt", cwd: app.fixtureDir }, { command: "touch b.txt", cwd: app.fixtureDir }] },
    });
    expect(batch.statusCode).toBe(200);
    expect(batch.json()).toMatchObject({ classification: "read_only", execution_channel: "sandboxed_read_shell" });
    expect(batch.json().results).toHaveLength(2);
    expect(batch.json().results[1]).toMatchObject({ status: "failed" });
    expect(await app.exists("b.txt")).toBe(false);
  });

  test("supports Streamable HTTP MCP initialize, tool discovery, and a read call", async () => {
    const app = await createTestApp();
    apps.push(app);
    const mcp = await initializeMcp(app);
    const listed = await app.fastify.inject({ method: "POST", url: "/mcp", headers: mcp.headers, payload: { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} } });
    expect(listed.statusCode).toBe(200);
    expect(listed.body).toContain("run_shell_command");
    expect(listed.body).toContain("inspect_config");
    expect(listed.body).toContain("run_project_task");
    expect(listed.body).toContain("write_text_document");
    expect(listed.body).toContain("patch_text_document");
    expect(listed.body).toContain("move_text_document");
    expect(listed.body).toContain("get_git_status");
    expect(listed.body).toContain("git_stage");
    expect(listed.body).toContain("git_unstage");
    expect(listed.body).toContain("prepare_git_commit");
    expect(listed.body).toContain("prepare_existing_script_run");
    expect(listed.body).toContain("cancel_proposal");
    expect(listed.body).toContain("execute_proposal");
    expect(listed.body).toContain("\"readOnlyHint\":false");
    expect(listed.body).toContain("\"destructiveHint\":true");
    expect(listed.body).toContain("\"idempotentHint\":true");
    expect(listed.body).toContain("readOnlyHint");
    const tools = listed.json().result.tools as Array<{ name: string; annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean } }>;
    for (const name of ["run_shell_command", "inspect_config", "run_project_task", "get_git_status", "prepare_git_commit"]) {
      expect(tools.find((tool) => tool.name === name)?.annotations).toMatchObject({ readOnlyHint: true, openWorldHint: false });
    }
    for (const name of ["write_text_document", "patch_text_document", "move_text_document"]) {
      expect(tools.find((tool) => tool.name === name)?.annotations).toMatchObject({
        readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false,
      });
    }
    for (const name of ["git_stage", "git_unstage", "cancel_proposal"]) {
      expect(tools.find((tool) => tool.name === name)?.annotations).toMatchObject({
        readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false,
      });
    }
    expect(tools.find((tool) => tool.name === "prepare_existing_script_run")?.annotations).toMatchObject({
      readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false,
    });
    const called = await app.fastify.inject({ method: "POST", url: "/mcp", headers: mcp.headers, payload: { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "run_shell_command", arguments: { command: "printf hello", cwd: app.fixtureDir } } } });
    expect(called.statusCode).toBe(200);
    expect(called.body).toContain("hello");
    const { "content-type": _contentType, ...closeHeaders } = mcp.headers;
    const closed = await app.fastify.inject({
      method: "DELETE",
      url: "/mcp",
      headers: { ...closeHeaders, "mcp-protocol-version": "2025-03-26" },
    });
    expect(closed.statusCode, closed.body).toBe(200);
  });

  test("execute_proposal rejects any command or cwd override at the MCP schema", async () => {
    const app = await createTestApp({ approvalSmokeEnabled: true });
    apps.push(app);
    const prepared = await app.fastify.inject({ method: "POST", url: "/v1/shell/approval-smoke", headers: app.authHeaders });
    expect(prepared.statusCode).toBe(202);
    const approvalId = prepared.json().approval_id as string;
    const mcp = await initializeMcp(app);

    const called = await app.fastify.inject({
      method: "POST",
      url: "/mcp",
      headers: mcp.headers,
      payload: { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "execute_proposal", arguments: { approval_id: approvalId, command: "touch bypass", cwd: "/tmp" } } },
    });

    expect(called.statusCode).toBe(200);
    expect(called.body).toContain("Invalid arguments");
    await expect((await import("node:fs/promises")).readdir(app.smokeDir).then((files) => files.filter((name) => name.endsWith(".empty")))).resolves.toHaveLength(0);
    const restOverride = await app.fastify.inject({ method: "POST", url: `/v1/shell/approvals/${approvalId}/execute`, headers: app.authHeaders, payload: { command: "touch bypass" } });
    expect(restOverride.statusCode).toBe(400);
  });

  test("caps concurrent MCP session initialization", async () => {
    const app = await createTestApp();
    apps.push(app);
    const headers = { ...app.authHeaders, accept: "application/json, text/event-stream", "content-type": "application/json" };
    const responses = await Promise.all(Array.from({ length: 65 }, (_, index) => app.fastify.inject({
      method: "POST",
      url: "/mcp",
      headers,
      payload: {
        jsonrpc: "2.0",
        id: index + 1,
        method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "limit-test", version: "1.0.0" } },
      },
    })));
    expect(responses.filter((response) => response.statusCode === 429)).toHaveLength(1);
  });

  test.skipIf(process.env.SHELLBRIDGE_SANDBOXED_PROJECT_TASK === "1")("expires pending proposals consistently and never executes them", async () => {
    const app = await createTestApp({ approvalSmokeEnabled: true, proposalTtlMs: -1 });
    apps.push(app);
    const prepared = await app.fastify.inject({ method: "POST", url: "/v1/shell/approval-smoke", headers: app.authHeaders });
    expect(prepared.statusCode).toBe(202);
    const approvalId = prepared.json().approval_id as string;

    const inspected = await app.fastify.inject({ method: "GET", url: `/v1/shell/approvals/${approvalId}`, headers: app.authHeaders });
    expect(inspected.json()).toMatchObject({ status: "expired" });
    const executed = await app.fastify.inject({ method: "POST", url: `/v1/shell/approvals/${approvalId}/execute`, headers: app.authHeaders });
    expect(executed.statusCode).toBe(409);
    expect(executed.json()).toMatchObject({ error: "approval_not_executable", status: "expired" });
    const db = new Database(databasePath(app), { readonly: true });
    expect(db.prepare("SELECT state FROM proposals WHERE id=?").get(approvalId)).toEqual({ state: "expired" });
    db.close();
  });

  test.skipIf(process.env.SHELLBRIDGE_SANDBOXED_PROJECT_TASK === "1")("executes the fixed smoke proposal once and prevents concurrent replay", async () => {
    const app = await createTestApp({ approvalSmokeEnabled: true });
    apps.push(app);
    const prepared = await app.fastify.inject({ method: "POST", url: "/v1/shell/approval-smoke", headers: app.authHeaders });
    expect(prepared.statusCode).toBe(202);
    const approvalId = prepared.json().approval_id as string;

    const attempts = await Promise.all([
      app.fastify.inject({ method: "POST", url: `/v1/shell/approvals/${approvalId}/execute`, headers: app.authHeaders }),
      app.fastify.inject({ method: "POST", url: `/v1/shell/approvals/${approvalId}/execute`, headers: app.authHeaders }),
    ]);

    expect(attempts.map(({ statusCode }) => statusCode).sort()).toEqual([200, 409]);
    const files = await (await import("node:fs/promises")).readdir(app.smokeDir);
    expect(files.filter((name) => name.endsWith(".empty"))).toHaveLength(1);
    const replay = await app.fastify.inject({ method: "POST", url: `/v1/shell/approvals/${approvalId}/execute`, headers: app.authHeaders });
    expect(replay.statusCode).toBe(409);
  });

  test("does not let the MCP layer bypass blocked, redaction, or path policy", async () => {
    const app = await createTestApp({ files: { "public.txt": "safe-model\n", "credential.log": "test-bearer-token\n" } });
    apps.push(app);
    const mcp = await initializeMcp(app);
    const call = (id: number, command: string, cwd: string) => app.fastify.inject({
      method: "POST",
      url: "/mcp",
      headers: mcp.headers,
      payload: { jsonrpc: "2.0", id, method: "tools/call", params: { name: "run_shell_command", arguments: { command, cwd } } },
    });

    const blocked = await call(6, "cat /etc/shadow", app.fixtureDir);
    const blockedResult = JSON.parse(blocked.json().result.content[0].text);
    expect(blockedResult).toMatchObject({ status: "failed", execution_channel: "sandboxed_read_shell" });
    expect(blocked.body).not.toContain("root:");
    const outside = await call(7, "cat passwd", "/etc");
    expect(outside.body).toContain("cwd_outside_sandbox_roots");
    const publicRead = await call(8, "cat public.txt | sed 's/safe/SAFE/'", app.fixtureDir);
    expect(publicRead.body).toContain("SAFE-model");
    const complex = await call(9, "for n in 1 2; do printf '%s' \"$n\"; done", app.fixtureDir);
    expect(complex.body).toContain("12");
    expect(complex.body).not.toContain("approval_id");
    const redacted = await call(10, "cat credential.log", app.fixtureDir);
    expect(redacted.body).toContain("[REDACTED length=17]");
    expect(redacted.body).not.toContain("test-bearer-token");
    const databaseBytes = await (await import("node:fs/promises")).readFile(databasePath(app));
    expect(databaseBytes.toString("utf8")).not.toContain("test-bearer-token");
  });

  test("rejects a legacy df proposal and the known bad approval id without execution", async () => {
    const app = await createTestApp({ writeActionsEnabled: true });
    apps.push(app);
    const approvalId = "3c5af897-3ee2-4c06-a315-3e69a4b861f0";
    const payload = { kind: "shell_command", command: "df -hT", cwd: app.fixtureDir, timeout_ms: 15_000, max_output_bytes: 32 * 1024 };
    const hash = createHash("sha256").update(JSON.stringify(payload)).digest("hex");
    const db = new Database(databasePath(app));
    db.prepare("INSERT INTO proposals (id,principal_id,state,payload,hash,expires_at,created_at) VALUES (?,'owner-1','pending',?,?,?,?)").run(approvalId, sealTestProposal(payload), hash, new Date(Date.now() + 60_000).toISOString(), new Date().toISOString());
    db.close();

    const cancelled = await app.fastify.inject({ method: "POST", url: `/v1/shell/approvals/${approvalId}/cancel`, headers: app.authHeaders });
    expect(cancelled.json()).toMatchObject({ approval_id: approvalId, status: "cancelled" });
    const executed = await app.fastify.inject({ method: "POST", url: `/v1/shell/approvals/${approvalId}/execute`, headers: app.authHeaders });

    expect(executed.statusCode).toBe(409);
    expect(executed.json()).toMatchObject({ error: "approval_not_executable", status: "cancelled" });
  });

  test.skipIf(process.env.SHELLBRIDGE_SANDBOXED_PROJECT_TASK === "1")("validates proposal principal, hash, legacy kind, and smoke state before claiming", async () => {
    const principalApp = await createTestApp({ approvalSmokeEnabled: true });
    apps.push(principalApp);
    const principalPrepared = await principalApp.fastify.inject({ method: "POST", url: "/v1/shell/approval-smoke", headers: principalApp.authHeaders });
    expect(principalPrepared.statusCode).toBe(202);
    const principalId = principalPrepared.json().approval_id as string;
    let db = new Database(databasePath(principalApp));
    db.prepare("UPDATE proposals SET principal_id='other-principal' WHERE id=?").run(principalId);
    db.close();
    const principalExecution = await principalApp.fastify.inject({ method: "POST", url: `/v1/shell/approvals/${principalId}/execute`, headers: principalApp.authHeaders });
    expect(principalExecution.statusCode).toBe(404);

    const hashApp = await createTestApp({ approvalSmokeEnabled: true });
    apps.push(hashApp);
    const hashPrepared = await hashApp.fastify.inject({ method: "POST", url: "/v1/shell/approval-smoke", headers: hashApp.authHeaders });
    expect(hashPrepared.statusCode).toBe(202);
    const hashId = hashPrepared.json().approval_id as string;
    db = new Database(databasePath(hashApp));
    db.prepare("UPDATE proposals SET hash=? WHERE id=?").run("0".repeat(64), hashId);
    db.close();
    const hashExecution = await hashApp.fastify.inject({ method: "POST", url: `/v1/shell/approvals/${hashId}/execute`, headers: hashApp.authHeaders });
    expect(hashExecution.statusCode).toBe(409);
    expect(hashExecution.json()).toMatchObject({ error: "proposal_integrity_failed" });

    const blockedApp = await createTestApp({ writeActionsEnabled: true });
    apps.push(blockedApp);
    const blockedId = "11111111-1111-4111-8111-111111111111";
    const blockedPayload = { kind: "shell_command", command: "cat /etc/shadow", cwd: blockedApp.fixtureDir, timeout_ms: 15_000, max_output_bytes: 32 * 1024 };
    db = new Database(databasePath(blockedApp));
    db.prepare("INSERT INTO proposals (id,principal_id,state,payload,hash,expires_at,created_at) VALUES (?,'owner-1','pending',?,?,?,?)").run(blockedId, sealTestProposal(blockedPayload), createHash("sha256").update(JSON.stringify(blockedPayload)).digest("hex"), new Date(Date.now() + 60_000).toISOString(), new Date().toISOString());
    db.close();
    const mcp = await initializeMcp(blockedApp);
    const blockedExecution = await blockedApp.fastify.inject({ method: "POST", url: "/mcp", headers: mcp.headers, payload: { jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "execute_proposal", arguments: { approval_id: blockedId } } } });
    expect(blockedExecution.body).toContain("unsupported_proposal_kind");
    expect(blockedExecution.body).not.toContain("root:");

    const stateApp = await createTestApp({ approvalSmokeEnabled: true });
    apps.push(stateApp);
    const statePrepared = await stateApp.fastify.inject({ method: "POST", url: "/v1/shell/approval-smoke", headers: stateApp.authHeaders });
    expect(statePrepared.statusCode).toBe(202);
    const stateId = statePrepared.json().approval_id as string;
    await (await import("node:fs/promises")).unlink(`${stateApp.smokeDir}/enabled`);
    const stateExecution = await stateApp.fastify.inject({ method: "POST", url: `/v1/shell/approvals/${stateId}/execute`, headers: stateApp.authHeaders });
    expect(stateExecution.statusCode).toBe(409);
    expect(stateExecution.json()).toMatchObject({ error: "approval_smoke_state_changed" });
  });

  test("authorizes a public MCP client with PKCE and rotates a refresh token", async () => {
    const app = await createTestApp();
    apps.push(app);
    const metadata = await app.fastify.inject({ method: "GET", url: "/.well-known/oauth-authorization-server" });
    expect(metadata.statusCode).toBe(200);
    expect(metadata.json().scopes_supported).toContain("offline_access");
    const registered = await app.fastify.inject({ method: "POST", url: "/oauth/register", payload: { client_name: "ChatGPT test", redirect_uris: ["https://chatgpt.com/aip/callback"], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" } });
    expect(registered.statusCode).toBe(201);
    const clientId = registered.json().client_id as string;
    const verifier = "a".repeat(64);
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const authorizeQuery = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: "https://chatgpt.com/aip/callback", resource: "https://bridge.example.test/mcp", scope: "mcp offline_access", state: "state-123", code_challenge: challenge, code_challenge_method: "S256" });
    const consent = await app.fastify.inject({ method: "GET", url: `/oauth/authorize?${authorizeQuery}` });
    expect(consent.statusCode).toBe(200);
    expect(consent.headers["content-security-policy"]).toContain("form-action 'self' https://chatgpt.com");
    const authorize = await app.fastify.inject({ method: "POST", url: "/oauth/authorize", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: "https://chatgpt.com/aip/callback", resource: "https://bridge.example.test/mcp", scope: "mcp offline_access", state: "state-123", code_challenge: challenge, code_challenge_method: "S256", owner_secret: "test-oauth-owner-secret" }).toString() });
    expect(authorize.statusCode).toBe(302);
    const location = new URL(authorize.headers.location!);
    expect(location.searchParams.get("state")).toBe("state-123");
    const code = location.searchParams.get("code")!;
    const token = await app.fastify.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "authorization_code", client_id: clientId, code, redirect_uri: "https://chatgpt.com/aip/callback", code_verifier: verifier }).toString() });
    expect(token.statusCode).toBe(200);
    expect(token.json()).toMatchObject({ token_type: "Bearer", scope: "mcp offline_access" });
    const auditDb = new Database(app.databasePath, { readonly: true });
    const tokenAudit = auditDb.prepare("SELECT event,outcome FROM oauth_audit WHERE client_id=? ORDER BY id").all(clientId);
    auditDb.close();
    expect(tokenAudit).toContainEqual({ event: "token_request", outcome: "received" });
    expect(tokenAudit).toContainEqual({ event: "authorization_code_exchanged", outcome: "success" });
    const replayedCode = await app.fastify.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "authorization_code", client_id: clientId, code, redirect_uri: "https://chatgpt.com/aip/callback", resource: "https://bridge.example.test/mcp", code_verifier: verifier }).toString() });
    expect(replayedCode.statusCode).toBe(400);
    const refreshed = await app.fastify.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "refresh_token", client_id: clientId, refresh_token: token.json().refresh_token }).toString() });
    expect(refreshed.statusCode).toBe(200);
    expect(refreshed.json().refresh_token).not.toBe(token.json().refresh_token);
    const replayedRefresh = await app.fastify.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "refresh_token", client_id: clientId, resource: "https://bridge.example.test/mcp", refresh_token: token.json().refresh_token }).toString() });
    expect(replayedRefresh.statusCode).toBe(400);
    const initialize = await app.fastify.inject({ method: "POST", url: "/mcp", headers: { authorization: `Bearer ${refreshed.json().access_token}`, accept: "application/json, text/event-stream", "content-type": "application/json" }, payload: { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "oauth-test", version: "1" } } } });
    expect(initialize.statusCode).toBe(200);
  });
});

import { mkdtemp, mkdir, rm, writeFile, access } from "node:fs/promises";
import { realpathSync, statSync } from "node:fs";
import { execFile } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import type { FastifyInstance, InjectOptions } from "fastify";
import { buildApp } from "../../src/app.js";
import { createConfig } from "../../src/config.js";
import { redact } from "../../src/redactor.js";

const execFileAsync = promisify(execFile);

function nestedProjectTaskSandbox(root: string) {
  return {
    async run(input: { command: string; cwd: string; timeoutMs: number; maxOutputBytes: number }) {
      const cwd = await (await import("node:fs/promises")).realpath(input.cwd);
      if (cwd !== root && !cwd.startsWith(`${root}${path.sep}`)) throw new Error("cwd_outside_sandbox_roots");
      if (input.command.includes("/etc/shadow") || /(^|[;&|]\s*)touch(?:\s|$)/.test(input.command)) {
        return { stdout: "", stderr: "read-only test sandbox denied command\n", exitCode: 1, truncated: false };
      }
      try {
        const result = await execFileAsync("/bin/bash", ["-lc", input.command], {
          cwd,
          timeout: input.timeoutMs,
          maxBuffer: input.maxOutputBytes,
          env: { PATH: "/usr/local/bin:/usr/bin:/bin", HOME: "/nonexistent", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
        });
        return { stdout: redact(result.stdout), stderr: redact(result.stderr), exitCode: 0, truncated: false };
      } catch (error) {
        const failure = error as { stdout?: string; stderr?: string; code?: number | string; killed?: boolean };
        return {
          stdout: redact(failure.stdout ?? ""),
          stderr: redact(failure.stderr ?? ""),
          exitCode: typeof failure.code === "number" ? failure.code : failure.killed ? 124 : 1,
          truncated: false,
        };
      }
    },
  };
}

export interface TestApp {
  fastify: FastifyInstance;
  fixtureDir: string;
  smokeDir: string;
  databasePath: string;
  authHeaders: Record<string, string>;
    injectCommand(body: {
    command: string;
    cwd?: string;
    timeout_ms?: number;
    max_output_bytes?: number;
  }): Promise<Awaited<ReturnType<FastifyInstance["inject"]>>>;
  exists(relativePath: string): Promise<boolean>;
  close(): Promise<void>;
}

export async function createTestApp(options: {
  files?: Record<string, string>;
  writeActionsEnabled?: boolean;
  documentWritesEnabled?: boolean;
  localGitWritesEnabled?: boolean;
  existingScriptRunsEnabled?: boolean;
  approvalSmokeEnabled?: boolean;
  proposalTtlMs?: number;
} = {}): Promise<TestApp> {
  const root = await mkdtemp(path.join(tmpdir(), "shellbridge-test-"));
  const fixtureDir = path.join(root, "fixture");
  await mkdir(fixtureDir);
  for (const [relativePath, contents] of Object.entries(options.files ?? {})) {
    await writeFile(path.join(fixtureDir, relativePath), contents, "utf8");
  }
  const smokeDir = path.join(root, "approval-smoke");
  await mkdir(smokeDir, { mode: 0o700 });
  const smokeEnabledFile = path.join(smokeDir, "enabled");
  if (options.approvalSmokeEnabled) await writeFile(smokeEnabledFile, "", { mode: 0o600 });

  const token = "test-bearer-token";
  const databasePath = path.join(root, "shellbridge.db");
  const config = createConfig({
      databasePath,
      token,
      encryptionKey: Buffer.alloc(32, 7).toString("base64"),
      defaultCwd: fixtureDir,
      inspectConfigRoots: [fixtureDir],
      inspectConfigDisclosures: {
        [path.join(fixtureDir, "service.json")]: {
          "/SERVICE_BASE_URL": ["https://api.example.test"],
          "/model": ["diagnostic-model"],
        },
      },
      sandboxReadRoots: [fixtureDir],
      sandboxBlockedPaths: [path.join(root, "shellbridge.db"), "/etc/shadow"],
      sandboxRequireCgroup: false,
      nativeHelperPath: path.resolve("dist/native/shellbridge-helper"),
      seccompFilterPath: path.resolve("dist/native/network-deny.bpf"),
      writeActionsEnabled: options.writeActionsEnabled ?? true,
      documentWritesEnabled: options.documentWritesEnabled ?? true,
      localGitWritesEnabled: options.localGitWritesEnabled ?? true,
      existingScriptRunsEnabled: options.existingScriptRunsEnabled ?? true,
      operationRoot: root,
      proposalTtlMs: options.proposalTtlMs ?? 60_000,
      oauthOwnerSecret: "test-oauth-owner-secret",
      publicBaseUrl: "https://bridge.example.test",
      oauthRedirectHosts: ["chatgpt.com"],
      approvalSmokeDirectory: smokeDir,
      approvalSmokeEnabledFile: smokeEnabledFile,
    });
  const fastify = await buildApp(
    config,
    {
      ...(process.env.SHELLBRIDGE_TEST_FAKE_SANDBOX === "1"
        ? { sandboxedShell: nestedProjectTaskSandbox(fixtureDir) }
        : {}),
      resolveApprovalSmokeState: asyncConfig => {
        const directory = realpathSync(asyncConfig.approvalSmokeDirectory);
        const enabledFile = realpathSync(asyncConfig.approvalSmokeEnabledFile);
        const enabledStat = statSync(enabledFile);
        return {
          directory,
          enabled_file: enabledFile,
          enabled_dev: enabledStat.dev,
          enabled_ino: enabledStat.ino,
          enabled_mtime_ms: enabledStat.mtimeMs,
        };
      },
    },
  );
  const authHeaders = { authorization: `Bearer ${token}` };

  return {
    fastify,
    fixtureDir,
    smokeDir,
    databasePath,
    authHeaders,
    injectCommand(body) {
      const options: InjectOptions = {
        method: "POST",
        url: "/v1/shell/commands",
        headers: authHeaders,
        payload: body,
      };
      return fastify.inject(options);
    },
    async exists(relativePath) {
      try {
        await access(path.join(fixtureDir, relativePath));
        return true;
      } catch {
        return false;
      }
    },
    async close() {
      await fastify.close();
      await rm(root, { recursive: true, force: true });
    },
  };
}

import path from "node:path";

export interface GatewayConfig {
  listenPort: number;
  databasePath: string;
  token: string;
  encryptionKey: Buffer;
  defaultCwd: string;
  writeActionsEnabled: boolean;
  documentWritesEnabled: boolean;
  localGitWritesEnabled: boolean;
  existingScriptRunsEnabled: boolean;
  operationRoot: string;
  proposalTtlMs: number;
  publicBaseUrl: string;
  oauthOwnerSecret: string;
  oauthRedirectHosts: string[];
  mcpSessionTtlMs: number;
  mcpSessionLimit: number;
  approvalSmokeDirectory: string;
  approvalSmokeEnabledFile: string;
  nativeHelperPath: string;
  seccompFilterPath: string;
  bwrapPath: string;
  observerUid: number;
  observerGid: number;
  inspectConfigTargets: string[];
  inspectConfigRoots: string[];
  inspectConfigDisclosures: Record<string, Record<string, string[]>>;
  sandboxReadRoots: string[];
  sandboxBlockedPaths: string[];
  sandboxCgroupRoot: string;
  sandboxRequireCgroup: boolean;
}

export type ConfigOverrides = Omit<Partial<GatewayConfig>, "encryptionKey"> & { encryptionKey?: Buffer | string };

function environmentFlag(name: string, fallback: boolean): boolean {
  const value = process.env[name];
  if (value === undefined) return fallback;
  if (value === "1" || value.toLowerCase() === "true") return true;
  if (value === "0" || value.toLowerCase() === "false") return false;
  throw new Error(`${name} must be true, false, 1, or 0`);
}

function listenPort(value: number | string): number {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65_535) {
    throw new Error("SHELLBRIDGE_PORT must be an integer from 1 to 65535");
  }
  return parsed;
}

function normalizePublicBaseUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("SHELLBRIDGE_PUBLIC_BASE_URL must be an absolute HTTP(S) URL");
  }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new Error("SHELLBRIDGE_PUBLIC_BASE_URL must be an absolute HTTP(S) URL without credentials");
  }
  if (url.search || url.hash) {
    throw new Error("SHELLBRIDGE_PUBLIC_BASE_URL must not contain a query or fragment");
  }
  return url.toString().replace(/\/+$/, "");
}

function positiveInteger(name: string, fallback: number): number {
  const value = process.env[name];
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error(`${name} must be a positive integer`);
  return parsed;
}

const defaultRootSensitivePaths = [
  "/root/.ssh",
  "/root/.gnupg",
  "/root/.cloudflared",
  "/root/.git-credentials",
  "/root/.netrc",
  "/root/.npmrc",
  "/root/.pypirc",
  "/root/.authinfo",
  "/root/.authinfo.gpg",
  "/root/.password-store",
  "/root/.docker/config.json",
  "/root/.config/gh/hosts.yml",
  "/root/.config/git/credentials",
  "/root/.config/rclone/rclone.conf",
  "/root/.config/gcloud/credentials.db",
  "/root/.config/gcloud/access_tokens.db",
  "/root/.config/gcloud/legacy_credentials",
  "/root/.aws",
  "/root/.azure",
  "/root/.kube/config",
  "/root/.local/share/keyrings",
  "/root/.claude/.credentials.json",
  "/root/.claude/session-env",
  "/root/.claude/mcp-needs-auth-cache.json",
  "/root/.codex/auth.json",
  "/root/.codex/openrouter-token",
  "/root/.codex/openrouter_api_key",
  "/root/.codex/shell_snapshots",
  "/root/.gemini/oauth_creds.json",
  "/root/.gemini/google_accounts.json",
  "/root/.agently-cli/config.json",
  "/root/.Xauthority",
  "/root/.bash_history",
  "/root/.zsh_history",
  "/root/.python_history",
  "/root/.node_repl_history",
  "/root/.mysql_history",
  "/root/.psql_history",
  "/root/.lesshst",
  "/root/.pm2/rpc.sock",
  "/root/.pm2/pub.sock",
  "/root/.pm2/dump.pm2",
  "/root/.pm2/dump.pm2.bak",
  "/root/.mozilla/firefox",
  "/root/.config/google-chrome",
  "/root/.config/chromium",
  "/root/.config/microsoft-edge",
] as const;

export function createConfig(overrides: ConfigOverrides = {}): GatewayConfig {
  const token = overrides.token ?? process.env.SHELLBRIDGE_BEARER_TOKEN ?? "";
  if (!token) throw new Error("SHELLBRIDGE_BEARER_TOKEN is required");
  const configuredKey = overrides.encryptionKey;
  const key = typeof configuredKey === "string"
    ? Buffer.from(configuredKey, "base64")
    : configuredKey ?? Buffer.from(process.env.SHELLBRIDGE_DATA_KEY ?? "", "base64");
  if (key.length !== 32) throw new Error("SHELLBRIDGE_DATA_KEY must decode to 32 bytes");
  const oauthOwnerSecret = overrides.oauthOwnerSecret ?? process.env.SHELLBRIDGE_OAUTH_OWNER_SECRET ?? "";
  if (!oauthOwnerSecret) throw new Error("SHELLBRIDGE_OAUTH_OWNER_SECRET is required");
  const databasePath = overrides.databasePath ?? process.env.SHELLBRIDGE_DATABASE_PATH ?? "/var/lib/shellbridge/shellbridge.db";
  const defaultCwd = path.resolve(overrides.defaultCwd ?? process.env.SHELLBRIDGE_DEFAULT_CWD ?? "/root");
  const inspectConfigTargets = (overrides.inspectConfigTargets ?? process.env.SHELLBRIDGE_INSPECT_CONFIG_TARGETS?.split(":").filter(Boolean) ?? []).map((item) => path.resolve(item));
  let inspectConfigDisclosures: Record<string, Record<string, string[]>> = overrides.inspectConfigDisclosures ?? {};
  if (!overrides.inspectConfigDisclosures && process.env.SHELLBRIDGE_INSPECT_CONFIG_DISCLOSURES) {
    try {
      const parsed = JSON.parse(process.env.SHELLBRIDGE_INSPECT_CONFIG_DISCLOSURES) as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)
          || Object.values(parsed).some((selectors) => !selectors || typeof selectors !== "object" || Array.isArray(selectors)
            || Object.values(selectors).some((values) => !Array.isArray(values) || values.some((item) => typeof item !== "string")))) {
        throw new Error("invalid");
      }
      inspectConfigDisclosures = parsed as Record<string, Record<string, string[]>>;
    } catch {
      throw new Error("SHELLBRIDGE_INSPECT_CONFIG_DISCLOSURES must map path and selector to allowed value arrays");
    }
  }
  inspectConfigDisclosures = Object.fromEntries(Object.entries(inspectConfigDisclosures).map(
    ([target, selectors]) => [path.resolve(target), selectors],
  ));
  return {
    listenPort: listenPort(overrides.listenPort ?? process.env.SHELLBRIDGE_PORT ?? 8765),
    databasePath,
    token,
    encryptionKey: key,
    defaultCwd,
    writeActionsEnabled: overrides.writeActionsEnabled ?? environmentFlag("SHELLBRIDGE_WRITE_ACTIONS_ENABLED", false),
    documentWritesEnabled: overrides.documentWritesEnabled ?? environmentFlag("SHELLBRIDGE_DOCUMENT_WRITES_ENABLED", false),
    localGitWritesEnabled: overrides.localGitWritesEnabled ?? environmentFlag("SHELLBRIDGE_LOCAL_GIT_WRITES_ENABLED", false),
    existingScriptRunsEnabled: overrides.existingScriptRunsEnabled ?? environmentFlag("SHELLBRIDGE_EXISTING_SCRIPT_RUNS_ENABLED", false),
    operationRoot: path.resolve(overrides.operationRoot ?? process.env.SHELLBRIDGE_OPERATION_ROOT ?? "/root"),
    proposalTtlMs: overrides.proposalTtlMs ?? 10 * 60_000,
    publicBaseUrl: normalizePublicBaseUrl(overrides.publicBaseUrl ?? process.env.SHELLBRIDGE_PUBLIC_BASE_URL ?? "http://127.0.0.1:8765"),
    oauthOwnerSecret,
    oauthRedirectHosts: overrides.oauthRedirectHosts ?? (process.env.SHELLBRIDGE_OAUTH_REDIRECT_HOSTS?.split(",").filter(Boolean) ?? ["chatgpt.com", "chat.openai.com"]),
    mcpSessionTtlMs: overrides.mcpSessionTtlMs ?? positiveInteger("SHELLBRIDGE_MCP_SESSION_TTL_MS", 60 * 60_000),
    mcpSessionLimit: overrides.mcpSessionLimit ?? positiveInteger("SHELLBRIDGE_MCP_SESSION_LIMIT", 64),
    approvalSmokeDirectory: path.resolve(overrides.approvalSmokeDirectory ?? "/var/lib/shellbridge/approval-smoke"),
    approvalSmokeEnabledFile: path.resolve(overrides.approvalSmokeEnabledFile ?? "/var/lib/shellbridge/approval-smoke/enabled"),
    nativeHelperPath: path.resolve(overrides.nativeHelperPath ?? process.env.SHELLBRIDGE_NATIVE_HELPER_PATH ?? "dist/native/shellbridge-helper"),
    seccompFilterPath: path.resolve(overrides.seccompFilterPath ?? process.env.SHELLBRIDGE_SECCOMP_FILTER_PATH ?? "dist/native/network-deny.bpf"),
    bwrapPath: path.resolve(overrides.bwrapPath ?? process.env.SHELLBRIDGE_BWRAP_PATH ?? "/usr/bin/bwrap"),
    observerUid: overrides.observerUid ?? 65534,
    observerGid: overrides.observerGid ?? 65534,
    inspectConfigTargets,
    inspectConfigRoots: (overrides.inspectConfigRoots ?? process.env.SHELLBRIDGE_INSPECT_CONFIG_ROOTS?.split(":").filter(Boolean) ?? []).map((item) => path.resolve(item)),
    inspectConfigDisclosures,
    sandboxReadRoots: (overrides.sandboxReadRoots ?? process.env.SHELLBRIDGE_SANDBOX_READ_ROOTS?.split(":").filter(Boolean) ?? ["/root"]).map((item) => path.resolve(item)),
    sandboxBlockedPaths: [...new Set((overrides.sandboxBlockedPaths ?? [
      ...defaultRootSensitivePaths,
      path.resolve(databasePath),
      `${path.resolve(databasePath)}-wal`,
      `${path.resolve(databasePath)}-shm`,
      ...inspectConfigTargets,
      "/etc/shadow",
      "/etc/gshadow",
      "/etc/security/opasswd",
      "/etc/shellbridge",
      ...(process.env.SHELLBRIDGE_BLOCKED_PATHS?.split(":").filter(Boolean) ?? []),
    ]).map((item) => path.resolve(item)))],
    sandboxCgroupRoot: path.resolve(overrides.sandboxCgroupRoot ?? process.env.SHELLBRIDGE_CGROUP_ROOT ?? "/sys/fs/cgroup/shellbridge"),
    sandboxRequireCgroup: overrides.sandboxRequireCgroup ?? true,
  };
}
